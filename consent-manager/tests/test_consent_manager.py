import dataclasses
import os
from hashlib import sha256
from pathlib import Path

import yaml
from consent_router import ConsentManagerRouter, ConsentRecord, ShareRecord
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

HERE = Path(__file__).resolve().parent.parent


class RecordingStore:
    def __init__(self):
        self.records = []

    def persist(self, record):
        self.records.append(record)


class RecordingGateway:
    def __init__(self):
        self.forwarded = []
        self.transferred = []

    def forward(self, fiduciary_id, encrypted_token):
        self.forwarded.append((fiduciary_id, encrypted_token))

    def transfer(self, target, encrypted_payload):
        self.transferred.append((target, encrypted_payload))


def _encrypt(plaintext: bytes) -> bytes:
    """Stand-in for the Data Principal's client-side encryption."""
    key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    return nonce + AESGCM(key).encrypt(nonce, plaintext, None)


def _stored_values(record) -> str:
    return " ".join(str(v) for v in dataclasses.asdict(record).values())


def test_grant_stores_only_a_hash_and_forwards_the_token_unchanged():
    store, gateway = RecordingStore(), RecordingGateway()
    token = _encrypt(b'{"purpose": "marketing", "email": "asha@example.in"}')

    record = ConsentManagerRouter(store, gateway).route_consent_grant("p-1", "fid-abc", "marketing", token)

    assert isinstance(record, ConsentRecord)
    assert record.consent_token_hash == sha256(token).hexdigest()
    assert store.records == [record]
    assert gateway.forwarded == [("fid-abc", token)]
    assert "asha@example.in" not in _stored_values(record)
    assert token.hex() not in _stored_values(record)


def test_withdraw_stores_only_a_hash_and_forwards_the_token_unchanged():
    store, gateway = RecordingStore(), RecordingGateway()
    token = _encrypt(b'{"purpose": "marketing", "action": "WITHDRAW"}')

    record = ConsentManagerRouter(store, gateway).route_consent_withdraw("p-1", "fid-abc", "marketing", token)

    assert isinstance(record, ConsentRecord)
    assert record.action == "WITHDRAW"
    assert record.consent_token_hash == sha256(token).hexdigest()
    assert store.records == [record]
    assert gateway.forwarded == [("fid-abc", token)]
    assert token.hex() not in _stored_values(record)


def test_data_share_records_metadata_and_routes_ciphertext_to_target():
    store, gateway = RecordingStore(), RecordingGateway()
    payload = _encrypt(b"bank statement for p-1")

    record = ConsentManagerRouter(store, gateway).route_data_share("p-1", "fid-abc", "fid-def", payload)

    assert isinstance(record, ShareRecord)
    assert (record.source, record.target) == ("fid-abc", "fid-def")
    assert record.payload_hash == sha256(payload).hexdigest()
    assert gateway.transferred == [("fid-def", payload)]
    assert payload.hex() not in _stored_values(record)


def test_export_schema_example_is_well_formed():
    doc = yaml.safe_load((HERE / "export-schema.yaml").read_text(encoding="utf-8"))["consent_export"]
    assert doc["format"] == "application/json"
    types = [r["type"] for r in doc["records"]]
    assert types == ["CONSENT_GRANT", "CONSENT_WITHDRAWAL", "DATA_SHARE"]
    assert all("timestamp" in r for r in doc["records"])
    assert doc["retention"]["minimum_years"] == 7
