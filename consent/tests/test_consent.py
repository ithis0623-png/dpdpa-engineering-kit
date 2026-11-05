import uuid
from datetime import datetime, timezone
from hashlib import sha256

import pytest
from audit_chain import GENESIS_HASH, compute_event_hash, verify_chain
from consent_receipt import build_consent_receipt, verify_consent_receipt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient
from grant_endpoint import (
    InMemoryConsentStore,
    NoticeTranslation,
    NoticeVersion,
    Settings,
    create_app,
    get_settings,
)

KEY = Ed25519PrivateKey.generate()


def _receipt(**overrides):
    args = dict(
        principal_pseudonym="p-hmac",
        purpose_id="purpose-1",
        notice_version_id="nv-1",
        content_hash_shown=sha256(b"notice in Hindi").digest(),
        language_shown="hi",
        signing_key=KEY,
    )
    args.update(overrides)
    return build_consent_receipt(**args)


class TestReceipt:
    def test_signed_receipt_verifies(self):
        assert verify_consent_receipt(_receipt(), KEY.public_key())

    @pytest.mark.parametrize("field", ["purpose_id", "language_shown", "granted_at", "content_hash"])
    def test_any_edited_field_fails_verification(self, field):
        receipt = _receipt()
        receipt[field] = receipt[field] + "x"
        assert not verify_consent_receipt(receipt, KEY.public_key())

    def test_other_key_fails_verification(self):
        assert not verify_consent_receipt(_receipt(), Ed25519PrivateKey.generate().public_key())

    def test_explicit_timestamp_is_used(self):
        at = datetime(2026, 4, 13, 10, 30, tzinfo=timezone.utc)
        assert _receipt(granted_at=at)["granted_at"] == at.isoformat()


class TestAuditChain:
    def _chain(self, n=3):
        events, prev = [], GENESIS_HASH
        for i in range(n):
            e = {
                "consent_id": "c-1",
                "event_type": "VIEW",
                "event_payload": {"i": i},
                "occurred_at": f"2026-04-13T10:3{i}:00+00:00",
                "prev_event_hash": prev,
            }
            e["this_event_hash"] = compute_event_hash(
                prev, e["consent_id"], e["event_type"], e["event_payload"], e["occurred_at"]
            )
            events.append(e)
            prev = e["this_event_hash"]
        return events

    def test_hash_is_independent_of_payload_key_order(self):
        a = compute_event_hash(GENESIS_HASH, "c", "GRANT", {"a": 1, "b": 2}, "t")
        b = compute_event_hash(GENESIS_HASH, "c", "GRANT", {"b": 2, "a": 1}, "t")
        assert a == b

    def test_intact_chain_verifies(self):
        assert verify_chain(self._chain()) is None

    def test_edited_payload_is_detected_at_that_row(self):
        events = self._chain()
        events[1]["event_payload"] = {"i": 99}
        assert verify_chain(events) == 1

    def test_deleted_row_is_detected(self):
        events = self._chain()
        del events[1]
        assert verify_chain(events) == 1


@pytest.fixture
def api():
    store = InMemoryConsentStore()
    notice = NoticeVersion(notice_version_id=uuid.uuid4(), purpose_id=uuid.uuid4())
    content_hash = sha256(b"rendered Hindi notice").digest()
    store.notices[notice.notice_version_id] = notice
    store.translations[(notice.notice_version_id, "hi")] = NoticeTranslation(
        notice.notice_version_id, "hi", content_hash
    )
    settings = Settings(signing_key=KEY, pseudonym_key=b"test-pseudonym-key")
    client = TestClient(create_app(store, settings))
    body = {
        "principal_id": str(uuid.uuid4()),
        "notice_version_id": str(notice.notice_version_id),
        "language_shown": "hi",
        "content_hash_shown": content_hash.hex(),
    }
    return client, store, notice, body


class TestGrantEndpoint:
    def test_grant_returns_verifiable_receipt_and_chained_events(self, api):
        client, store, _, body = api
        resp = client.post("/v1/consents", json=body)
        assert resp.status_code == 201, resp.text
        receipt = resp.json()["receipt"]
        assert verify_consent_receipt(receipt, KEY.public_key())
        assert body["principal_id"] not in str(receipt)  # only the pseudonym is in the receipt

        record = store.consent_records[uuid.UUID(resp.json()["consent_id"])]
        assert record["granted_at"].isoformat() == receipt["granted_at"]
        assert [e["event_type"] for e in store.audit_events] == ["NOTICE_SHOWN", "GRANT"]
        assert verify_chain(store.audit_events) is None

    def test_superseded_notice_is_rejected(self, api):
        client, _, notice, body = api
        notice.superseded_at = datetime.now(timezone.utc)
        assert client.post("/v1/consents", json=body).status_code == 409

    def test_unknown_language_is_rejected(self, api):
        client, _, _, body = api
        body["language_shown"] = "ta"
        assert client.post("/v1/consents", json=body).json()["detail"] == "unsupported_language"

    def test_hash_mismatch_is_rejected(self, api):
        client, _, _, body = api
        body["content_hash_shown"] = sha256(b"a different notice").hexdigest()
        assert client.post("/v1/consents", json=body).json()["detail"] == "content_hash_mismatch"

    def test_failed_audit_write_rolls_back_the_record(self, api):
        client, store, _, body = api
        store.fail_on_event = "GRANT"
        with pytest.raises(RuntimeError):
            client.post("/v1/consents", json=body)
        assert store.consent_records == {}
        assert store.audit_events == []


class TestWithdrawEndpoint:
    def test_withdraw_consent_by_id_updates_status_and_chains_audit(self, api):
        client, store, _, body = api
        grant_resp = client.post("/v1/consents", json=body)
        assert grant_resp.status_code == 201
        consent_id = grant_resp.json()["consent_id"]

        withdraw_resp = client.post(f"/v1/consents/{consent_id}/withdraw")
        assert withdraw_resp.status_code == 200
        data = withdraw_resp.json()
        assert data["consent_id"] == consent_id
        assert data["status"] == "withdrawn"
        assert "withdrawn_at" in data

        record = store.consent_records[uuid.UUID(consent_id)]
        assert record["status"] == "withdrawn"
        assert datetime.fromisoformat(data["withdrawn_at"]) == record["withdrawn_at"]

        # Audit chain must now include NOTICE_SHOWN, GRANT, and WITHDRAW
        assert [e["event_type"] for e in store.audit_events] == ["NOTICE_SHOWN", "GRANT", "WITHDRAW"]
        assert verify_chain(store.audit_events) is None

    def test_withdraw_triggers_processor_fanout_and_erasure_event(self, api):
        client, store, _, body = api
        grant_resp = client.post("/v1/consents", json=body)
        consent_id = grant_resp.json()["consent_id"]

        # Configure downstream processors
        client.app.dependency_overrides[get_settings] = lambda: Settings(
            signing_key=KEY,
            pseudonym_key=b"test-pseudonym-key",
            processors=["analytics-processor-01", "payment-processor-02"],
        )

        withdraw_resp = client.post(f"/v1/consents/{consent_id}/withdraw")
        assert withdraw_resp.status_code == 200
        assert withdraw_resp.json()["processors_notified"] == [
            "analytics-processor-01",
            "payment-processor-02",
        ]
        assert len(store.processor_fanouts) == 2
        events = [e["event_type"] for e in store.audit_events]
        assert events == ["NOTICE_SHOWN", "GRANT", "WITHDRAW", "ERASURE_FANOUT", "ERASURE_FANOUT"]
        assert verify_chain(store.audit_events) is None

    def test_withdraw_parity_endpoint(self, api):
        client, store, notice, body = api
        grant_resp = client.post("/v1/consents", json=body)
        consent_id = grant_resp.json()["consent_id"]

        withdraw_body = {
            "principal_id": body["principal_id"],
            "purpose_id": str(notice.purpose_id),
        }
        withdraw_resp = client.post("/v1/consents/withdraw", json=withdraw_body)
        assert withdraw_resp.status_code == 200
        assert withdraw_resp.json()["consent_id"] == consent_id
        assert withdraw_resp.json()["status"] == "withdrawn"

    def test_withdraw_already_withdrawn_returns_409(self, api):
        client, _, _, body = api
        grant_resp = client.post("/v1/consents", json=body)
        consent_id = grant_resp.json()["consent_id"]

        assert client.post(f"/v1/consents/{consent_id}/withdraw").status_code == 200
        second = client.post(f"/v1/consents/{consent_id}/withdraw")
        assert second.status_code == 409
        assert second.json()["detail"] == "consent_already_withdrawn"

    def test_withdraw_nonexistent_returns_404(self, api):
        client, _, _, _ = api
        random_id = str(uuid.uuid4())
        resp = client.post(f"/v1/consents/{random_id}/withdraw")
        assert resp.status_code == 404
