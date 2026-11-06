import os

import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from field_encryption import DPDPAFieldEncryptor


class FakeKMS:
    """Wraps DEKs with a local AES-GCM key and, like AWS KMS, refuses a mismatched encryption context."""

    def __init__(self):
        self._kek = AESGCM.generate_key(bit_length=256)
        self.calls = []

    @staticmethod
    def _aad(key_id, context):
        return (key_id + "|" + "|".join(f"{k}={context[k]}" for k in sorted(context))).encode()

    def encrypt(self, key_id, plaintext, encryption_context):
        self.calls.append(("encrypt", key_id, dict(encryption_context)))
        nonce = os.urandom(12)
        return nonce + AESGCM(self._kek).encrypt(nonce, plaintext, self._aad(key_id, encryption_context))

    def decrypt(self, key_id, ciphertext, encryption_context):
        self.calls.append(("decrypt", key_id, dict(encryption_context)))
        return AESGCM(self._kek).decrypt(ciphertext[:12], ciphertext[12:], self._aad(key_id, encryption_context))


class RecordingAudit:
    def __init__(self):
        self.events = []

    def log(self, **event):
        self.events.append(event)


@pytest.fixture
def enc():
    kms, audit = FakeKMS(), RecordingAudit()
    return DPDPAFieldEncryptor(kms, audit, kek_id="alias/dpdpa-personal-data-test"), kms, audit


def test_round_trip(enc):
    encryptor, _, _ = enc
    field = encryptor.encrypt_field("asha@example.in", "email", "dp-1")
    assert b"asha" not in field.ciphertext
    assert len(field.nonce) == 12
    assert encryptor.decrypt_field(field, "email", "dp-1", requester="support-agent-7") == "asha@example.in"


def test_each_record_gets_its_own_dek_and_nonce(enc):
    encryptor, _, _ = enc
    a = encryptor.encrypt_field("same value", "email", "dp-1")
    b = encryptor.encrypt_field("same value", "email", "dp-1")
    assert a.wrapped_dek != b.wrapped_dek
    assert a.nonce != b.nonce
    assert a.ciphertext != b.ciphertext


def test_ciphertext_cannot_be_moved_to_another_principal(enc):
    """AAD and the KMS encryption context bind the ciphertext to its field and Data Principal."""
    encryptor, _, _ = enc
    field = encryptor.encrypt_field("asha@example.in", "email", "dp-1")
    with pytest.raises(InvalidTag):
        encryptor.decrypt_field(field, "email", "dp-2", requester="attacker")


def test_ciphertext_cannot_be_moved_to_another_field(enc):
    encryptor, _, _ = enc
    field = encryptor.encrypt_field("9876543210", "phone", "dp-1")
    with pytest.raises(InvalidTag):
        encryptor.decrypt_field(field, "email", "dp-1", requester="attacker")


def test_tampered_ciphertext_is_rejected(enc):
    encryptor, _, _ = enc
    field = encryptor.encrypt_field("asha@example.in", "email", "dp-1")
    field.ciphertext = bytes([field.ciphertext[0] ^ 1]) + field.ciphertext[1:]
    with pytest.raises(InvalidTag):
        encryptor.decrypt_field(field, "email", "dp-1", requester="support-agent-7")


def test_both_operations_are_audited_without_the_plaintext(enc):
    encryptor, kms, audit = enc
    field = encryptor.encrypt_field("asha@example.in", "email", "dp-1")
    encryptor.decrypt_field(field, "email", "dp-1", requester="support-agent-7")
    assert [e["event"] for e in audit.events] == ["field_encrypted", "field_decrypted"]
    assert audit.events[1]["requester"] == "support-agent-7"
    assert "asha@example.in" not in repr(audit.events)
    assert all(call[2]["purpose"] == "dpdpa_field_encryption" for call in kms.calls)


def test_pseudonymized_kms_context_prevents_cleartext_pii_in_cloudtrail():
    kms, audit = FakeKMS(), RecordingAudit()
    secret_key = b"super-secret-pseudonym-key-32b!"
    encryptor = DPDPAFieldEncryptor(
        kms, audit, kek_id="alias/dpdpa-personal-data-test", pseudonym_key=secret_key
    )
    raw_pid = "asha@example.in"  # Often used as principal ID in legacy apps
    field = encryptor.encrypt_field("+919876543210", "phone", raw_pid)

    # CloudTrail / KMS context must NOT contain the raw identifier
    kms_context = kms.calls[0][2]
    assert kms_context["principal"] != raw_pid
    assert len(kms_context["principal"]) == 64  # SHA-256 hex
    assert "asha@example.in" not in repr(kms.calls)

    # Decryption works with the same principal
    decrypted = encryptor.decrypt_field(field, "phone", raw_pid, requester="support-agent-7")
    assert decrypted == "+919876543210"

    # Decryption with another principal fails
    with pytest.raises(InvalidTag):
        encryptor.decrypt_field(field, "phone", "someone-else@example.in", requester="attacker")


def test_fallback_decrypt_for_legacy_unpseudonymized_records():
    kms, audit = FakeKMS(), RecordingAudit()
    # 1. Record encrypted BEFORE pseudonym_key is introduced
    legacy_encryptor = DPDPAFieldEncryptor(kms, audit, kek_id="alias/dpdpa-personal-data-test")
    raw_pid = "asha@example.in"
    field = legacy_encryptor.encrypt_field("secret-data", "notes", raw_pid)
    assert kms.calls[0][2]["principal"] == raw_pid

    # 2. When upgraded without legacy_context_fallback (default is False), decryption fails
    strict_encryptor = DPDPAFieldEncryptor(
        kms, audit, kek_id="alias/dpdpa-personal-data-test", pseudonym_key=b"migration-key-32b"
    )
    with pytest.raises(InvalidTag):
        strict_encryptor.decrypt_field(field, "notes", raw_pid, requester="strict-worker")

    # 3. When legacy_context_fallback=True is explicitly opted into, decryption succeeds
    fallback_encryptor = DPDPAFieldEncryptor(
        kms,
        audit,
        kek_id="alias/dpdpa-personal-data-test",
        pseudonym_key=b"migration-key-32b",
        legacy_context_fallback=True,
    )
    decrypted = fallback_encryptor.decrypt_field(field, "notes", raw_pid, requester="migration-worker")
    assert decrypted == "secret-data"

    # Verify that the fallback encryptor first attempted with pseudonym, then fell back to raw
    recent_decrypt_calls = [c for c in kms.calls if c[0] == "decrypt"]
    # 1 from strict_encryptor, 2 from fallback_encryptor
    assert len(recent_decrypt_calls) == 3
    assert recent_decrypt_calls[1][2]["principal"] != raw_pid  # pseudonym attempt failed
    assert recent_decrypt_calls[2][2]["principal"] == raw_pid  # fallback attempt succeeded


def test_non_mismatch_error_is_not_retried_with_raw_id():
    """Transient errors (network, throttling) must not trigger fallback with raw ID."""
    class FailingKMS(FakeKMS):
        def decrypt(self, key_id, ciphertext, encryption_context):
            self.calls.append(("decrypt", key_id, dict(encryption_context)))
            raise ConnectionError("KMS connection timed out")

    kms, audit = FailingKMS(), RecordingAudit()
    raw_pid = "asha@example.in"
    encryptor = DPDPAFieldEncryptor(
        kms,
        audit,
        kek_id="alias/dpdpa-personal-data-test",
        pseudonym_key=b"migration-key-32b",
        legacy_context_fallback=True,
    )
    field = DPDPAFieldEncryptor(FakeKMS(), audit, kek_id="k").encrypt_field("secret", "notes", raw_pid)

    with pytest.raises(ConnectionError, match="timed out"):
        encryptor.decrypt_field(field, "notes", raw_pid, requester="worker")

    # Only 1 decrypt call was made, and it was with the pseudonym (NEVER retried with raw ID)
    decrypt_calls = [c for c in kms.calls if c[0] == "decrypt"]
    assert len(decrypt_calls) == 1
    assert decrypt_calls[0][2]["principal"] != raw_pid
    assert raw_pid not in repr(kms.calls)


def test_rewrap_field_migrates_legacy_record_and_disables_fallback():
    kms, audit = FakeKMS(), RecordingAudit()
    legacy_encryptor = DPDPAFieldEncryptor(kms, audit, kek_id="alias/dpdpa-personal-data-test")
    raw_pid = "asha@example.in"
    legacy_field = legacy_encryptor.encrypt_field("secret-payload", "notes", raw_pid)

    # Rewrap with migration encryptor
    migration_encryptor = DPDPAFieldEncryptor(
        kms,
        audit,
        kek_id="alias/dpdpa-personal-data-test",
        pseudonym_key=b"migration-key-32b",
        legacy_context_fallback=True,
    )
    rewrapped_field = migration_encryptor.rewrap_field(legacy_field, "notes", raw_pid)

    # Now verify that a strict encryptor (legacy_context_fallback=False) decrypts the rewrapped record
    strict_encryptor = DPDPAFieldEncryptor(
        kms,
        audit,
        kek_id="alias/dpdpa-personal-data-test",
        pseudonym_key=b"migration-key-32b",
        legacy_context_fallback=False,
    )
    decrypted = strict_encryptor.decrypt_field(rewrapped_field, "notes", raw_pid, requester="production-app")
    assert decrypted == "secret-payload"

    # Last decrypt call used the pseudonym on its first (and only) attempt
    last_call = kms.calls[-1]
    assert last_call[0] == "decrypt"
    assert last_call[2]["principal"] != raw_pid
    assert len(last_call[2]["principal"]) == 64


def test_wrong_principal_still_fails_with_fallback():
    kms, audit = FakeKMS(), RecordingAudit()
    legacy_encryptor = DPDPAFieldEncryptor(kms, audit, kek_id="alias/dpdpa-personal-data-test")
    field = legacy_encryptor.encrypt_field("secret-data", "notes", "dp-1")

    upgraded_encryptor = DPDPAFieldEncryptor(
        kms,
        audit,
        kek_id="alias/dpdpa-personal-data-test",
        pseudonym_key=b"migration-key-32b",
        legacy_context_fallback=True,
    )
    with pytest.raises(InvalidTag):
        upgraded_encryptor.decrypt_field(field, "notes", "dp-2", requester="attacker")
