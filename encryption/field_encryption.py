"""
field_level_encryption.py

Implements field-level encryption for personal data fields
using AES-256-GCM with envelope encryption. Each record gets
a unique Data Encryption Key (DEK) wrapped by a KMS-managed
Key Encryption Key (KEK).

Maps to: Rule 6(1)(a) — encryption of personal data
"""
import hashlib
import hmac
import os
from dataclasses import dataclass
from datetime import datetime, timezone

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class KMSContextMismatchError(Exception):
    """Raised when KMS decryption fails due to an encryption context mismatch."""
    pass


@dataclass
class EncryptedField:
    """Represents an encrypted personal data field."""
    ciphertext: bytes
    nonce: bytes          # 96-bit nonce for AES-256-GCM
    kek_id: str           # KMS key ID used to wrap the DEK
    wrapped_dek: bytes    # DEK encrypted by KMS KEK
    encrypted_at: datetime
    algorithm: str = "AES-256-GCM"


class DPDPAFieldEncryptor:
    """Encrypts personal data fields per Rule 6(1)(a).

    Uses envelope encryption:
    1. Generate a random 256-bit DEK per record
    2. Encrypt the field value with DEK using AES-256-GCM
    3. Wrap the DEK with a KMS-managed KEK
    4. Store the wrapped DEK alongside the ciphertext
    5. Log the encryption event for Rule 6(1)(c) audit
    """

    def __init__(
        self,
        kms_client,
        audit_logger,
        kek_id: str,
        pseudonym_key: bytes | None = None,
        legacy_context_fallback: bool = False,
        context_mismatch_exception: type[BaseException] | tuple[type[BaseException], ...] = (
            KMSContextMismatchError,
            InvalidTag,
        ),
    ):
        self.kms = kms_client
        self.audit = audit_logger
        self.kek_id = kek_id
        self.pseudonym_key = pseudonym_key
        self.legacy_context_fallback = legacy_context_fallback
        self.context_mismatch_exception = context_mismatch_exception

    def _context_principal(self, data_principal_id: str) -> str:
        """Pseudonymise the Data Principal ID for KMS encryption context to prevent
        plaintext PII from being logged in CloudTrail / cloud audit trails."""
        if self.pseudonym_key:
            return hmac.new(self.pseudonym_key, data_principal_id.encode("utf-8"), hashlib.sha256).hexdigest()
        return data_principal_id

    def encrypt_field(
        self,
        plaintext: str,
        field_name: str,
        data_principal_id: str,
    ) -> EncryptedField:
        """Encrypt a single personal data field.

        Args:
            plaintext: The field value to encrypt
            field_name: Name of the field (for audit logging)
            data_principal_id: ID of the Data Principal

        Returns:
            EncryptedField with ciphertext and key metadata
        """
        # Step 1: Generate a random 256-bit DEK
        dek = AESGCM.generate_key(bit_length=256)

        # Step 2: Encrypt the field with AES-256-GCM
        aesgcm = AESGCM(dek)
        nonce = os.urandom(12)  # 96-bit nonce
        ciphertext = aesgcm.encrypt(
            nonce,
            plaintext.encode("utf-8"),
            # Additional authenticated data: field name + principal ID
            # Binds ciphertext to its intended context
            f"{field_name}:{data_principal_id}".encode("utf-8"),
        )

        # Step 3: Wrap the DEK with KMS KEK
        context_principal = self._context_principal(data_principal_id)
        wrapped_dek = self.kms.encrypt(
            key_id=self.kek_id,
            plaintext=dek,
            encryption_context={
                "field": field_name,
                "principal": context_principal,
                "purpose": "dpdpa_field_encryption",
            },
        )

        # Step 4: Audit log the encryption event (Rule 6(1)(c))
        self.audit.log(
            event="field_encrypted",
            field_name=field_name,
            data_principal_id=data_principal_id,
            kek_id=self.kek_id,
            algorithm="AES-256-GCM",
            timestamp=datetime.now(timezone.utc).isoformat(),
        )

        # Drop the plaintext DEK reference. Python bytes are immutable, so this
        # cannot wipe the key from memory; if that matters, do the key handling
        # in a KMS/HSM call (e.g. GenerateDataKey + Decrypt) rather than here.
        del dek

        return EncryptedField(
            ciphertext=ciphertext,
            nonce=nonce,
            kek_id=self.kek_id,
            wrapped_dek=wrapped_dek,
            encrypted_at=datetime.now(timezone.utc),
        )

    def decrypt_field(
        self,
        encrypted: EncryptedField,
        field_name: str,
        data_principal_id: str,
        requester: str,
    ) -> str:
        """Decrypt a personal data field.

        Every decryption event is logged per Rule 6(1)(c).

        Migration note:
            When `pseudonym_key` is configured, newly encrypted fields use an HMAC-SHA256
            pseudonym of `data_principal_id` in the KMS encryption context.
            Because KMS enforces exact encryption context matching, records wrapped
            prior to configuring `pseudonym_key` (which used raw `data_principal_id`)
            will fail decryption under the pseudonymized context.
            To support seamless zero-downtime migration, if decryption with the
            pseudonym fails, this method automatically falls back to attempting
            decryption with the legacy un-pseudonymized `data_principal_id`.
        """
        # Step 1: Unwrap DEK via KMS
        context_principal = self._context_principal(data_principal_id)
        try:
            dek = self.kms.decrypt(
                key_id=encrypted.kek_id,
                ciphertext=encrypted.wrapped_dek,
                encryption_context={
                    "field": field_name,
                    "principal": context_principal,
                    "purpose": "dpdpa_field_encryption",
                },
            )
        except self.context_mismatch_exception:
            # Migration fallback: ONLY on context mismatch, and ONLY if legacy_context_fallback is explicitly True.
            # Warning: Falling back re-exposes the raw data_principal_id to cloud KMS audit logs (CloudTrail).
            if self.legacy_context_fallback and self.pseudonym_key and context_principal != data_principal_id:
                dek = self.kms.decrypt(
                    key_id=encrypted.kek_id,
                    ciphertext=encrypted.wrapped_dek,
                    encryption_context={
                        "field": field_name,
                        "principal": data_principal_id,
                        "purpose": "dpdpa_field_encryption",
                    },
                )
            else:
                raise

        # Step 2: Decrypt field with AES-256-GCM
        aesgcm = AESGCM(dek)
        plaintext = aesgcm.decrypt(
            encrypted.nonce,
            encrypted.ciphertext,
            f"{field_name}:{data_principal_id}".encode("utf-8"),
        )

        # Step 3: Audit log the decryption event (Rule 6(1)(c))
        self.audit.log(
            event="field_decrypted",
            field_name=field_name,
            data_principal_id=data_principal_id,
            requester=requester,
            kek_id=encrypted.kek_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
        )

        # Drop the plaintext DEK reference (see the note in encrypt_field)
        del dek

        return plaintext.decode("utf-8")

    def rewrap_field(
        self,
        encrypted: EncryptedField,
        field_name: str,
        data_principal_id: str,
        requester: str = "rewrap-migration",
    ) -> EncryptedField:
        """Decrypts a field and re-encrypts it under the current pseudonymized context.

        Allows rotating legacy records encrypted with raw principal IDs to use the
        pseudonymized context so `legacy_context_fallback` can safely be turned off.
        """
        plaintext = self.decrypt_field(
            encrypted=encrypted,
            field_name=field_name,
            data_principal_id=data_principal_id,
            requester=requester,
        )
        return self.encrypt_field(
            plaintext=plaintext,
            field_name=field_name,
            data_principal_id=data_principal_id,
        )
