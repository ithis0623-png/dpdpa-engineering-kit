# FastAPI handler for a DPDPA consent management API grant endpoint.
# This is the single most important code path in the system: it binds
# notice content, principal action, and signed evidence into one atomic
# transaction. Any failure mode here is a burden-of-proof failure mode.
#
# The handler is the one from the article. The models, the ConsentStore
# interface and InMemoryConsentStore are added so it runs; swap the store
# for one backed by consent/schema.sql in production.
import hashlib
import hmac
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Protocol

from audit_chain import GENESIS_HASH, compute_event_hash
from consent_receipt import build_consent_receipt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import APIRouter, Depends, FastAPI, HTTPException
from pydantic import BaseModel, Field


class ConsentGrantRequest(BaseModel):
    principal_id: uuid.UUID
    notice_version_id: uuid.UUID
    language_shown: str
    content_hash_shown: bytes  # hex in JSON; checked against the stored translation hash

    model_config = {"ser_json_bytes": "hex", "val_json_bytes": "hex"}


class ConsentGrantResponse(BaseModel):
    consent_id: uuid.UUID
    receipt: dict


class ConsentWithdrawRequest(BaseModel):
    principal_id: uuid.UUID
    purpose_id: uuid.UUID


class ConsentWithdrawResponse(BaseModel):
    consent_id: uuid.UUID
    status: str
    withdrawn_at: datetime
    processors_notified: list[str] = Field(default_factory=list)
    withdrawn_consent_ids: list[uuid.UUID] = Field(default_factory=list)


@dataclass
class NoticeVersion:
    notice_version_id: uuid.UUID
    purpose_id: uuid.UUID
    superseded_at: datetime | None = None


@dataclass
class NoticeTranslation:
    notice_version_id: uuid.UUID
    language_code: str
    content_hash: bytes


class ConsentStore(Protocol):
    async def fetch_notice_version(self, notice_version_id: uuid.UUID) -> NoticeVersion | None: ...
    async def fetch_notice_translation(
        self, notice_version_id: uuid.UUID, language_code: str
    ) -> NoticeTranslation | None: ...
    def transaction(self): ...
    async def insert_consent_record(self, **fields) -> uuid.UUID: ...
    async def append_audit_event(self, consent_id: uuid.UUID, event_type: str, payload: dict) -> None: ...
    async def fetch_consent_record_for_update(self, consent_id: uuid.UUID) -> dict | None:
        """Fetch a consent record by ID. In durable stores (e.g., PostgreSQL), this must
        acquire an exclusive row-level lock (SELECT ... FOR UPDATE) inside the transaction
        to prevent concurrent withdrawals from creating duplicate audit events."""
        ...
    async def fetch_active_consents_for_update(
        self, principal_id: uuid.UUID, purpose_id: uuid.UUID
    ) -> list[dict]:
        """Fetch all active ('granted') consent records for a principal and purpose.
        In durable stores (e.g. PostgreSQL), this must acquire exclusive row locks
        (SELECT ... FOR UPDATE) to withdraw all active grants atomically."""
        ...
    async def withdraw_consent_record(self, consent_id: uuid.UUID, withdrawn_at: datetime) -> None: ...
    async def record_processor_fanout(self, consent_id: uuid.UUID, processor_id: str) -> None: ...


@dataclass
class InMemoryConsentStore:
    """Reference store for tests and local runs. Not durable, not concurrent-safe."""

    notices: dict = field(default_factory=dict)
    translations: dict = field(default_factory=dict)
    consent_records: dict = field(default_factory=dict)
    audit_events: list = field(default_factory=list)
    processor_fanouts: list = field(default_factory=list)
    fail_on_event: str | None = None  # test hook: raise when this event type is appended

    async def fetch_notice_version(self, notice_version_id):
        return self.notices.get(notice_version_id)

    async def fetch_notice_translation(self, notice_version_id, language_code):
        return self.translations.get((notice_version_id, language_code))

    async def fetch_consent_record_for_update(self, consent_id: uuid.UUID) -> dict | None:
        rec = self.consent_records.get(consent_id)
        if rec:
            return {"consent_id": consent_id, **rec}
        return None

    async def fetch_active_consents_for_update(
        self, principal_id: uuid.UUID, purpose_id: uuid.UUID
    ) -> list[dict]:
        matches = []
        for cid, rec in self.consent_records.items():
            if (
                rec.get("principal_id") == principal_id
                and rec.get("purpose_id") == purpose_id
                and rec.get("status") == "granted"
            ):
                matches.append({"consent_id": cid, **rec})
        return matches

    async def withdraw_consent_record(self, consent_id: uuid.UUID, withdrawn_at: datetime) -> None:
        if consent_id in self.consent_records:
            self.consent_records[consent_id]["status"] = "withdrawn"
            self.consent_records[consent_id]["withdrawn_at"] = withdrawn_at

    async def record_processor_fanout(self, consent_id: uuid.UUID, processor_id: str) -> None:
        self.processor_fanouts.append({
            "consent_id": consent_id,
            "processor_id": processor_id,
            "status": "pending",
        })

    @asynccontextmanager
    async def transaction(self):
        records = dict(self.consent_records)
        events = list(self.audit_events)
        fanouts = list(self.processor_fanouts)
        try:
            yield
        except Exception:
            self.consent_records = records
            self.audit_events = events
            self.processor_fanouts = fanouts
            raise

    async def insert_consent_record(self, **fields):
        consent_id = uuid.uuid4()
        self.consent_records[consent_id] = {"status": "granted", **fields}
        return consent_id

    async def append_audit_event(self, consent_id, event_type, payload):
        if event_type == self.fail_on_event:
            raise RuntimeError(f"simulated failure writing {event_type}")
        prev = next(
            (e["this_event_hash"] for e in reversed(self.audit_events) if e["consent_id"] == str(consent_id)),
            GENESIS_HASH,
        )
        occurred_at = datetime.now(timezone.utc).isoformat()
        self.audit_events.append({
            "consent_id": str(consent_id),
            "event_type": event_type,
            "event_payload": payload,
            "occurred_at": occurred_at,
            "prev_event_hash": prev,
            "this_event_hash": compute_event_hash(prev, str(consent_id), event_type, payload, occurred_at),
        })


@dataclass
class Settings:
    signing_key: Ed25519PrivateKey
    pseudonym_key: bytes  # HMAC key; keep it in a KMS or vault, never next to the data
    processors: list[str] = field(default_factory=list)


def hmac_sha256(value: str, key: bytes) -> bytes:
    return hmac.new(key, value.encode("utf-8"), hashlib.sha256).digest()


router = APIRouter()


def get_store() -> ConsentStore:
    raise NotImplementedError("override with app.dependency_overrides or create_app()")


def get_settings() -> Settings:
    raise NotImplementedError("override with app.dependency_overrides or create_app()")


@router.post("/v1/consents", status_code=201)
async def grant_consent(
    body: ConsentGrantRequest,
    db: ConsentStore = Depends(get_store),
    settings: Settings = Depends(get_settings),
) -> ConsentGrantResponse:
    # 1. Verify the notice version is currently active.
    notice = await db.fetch_notice_version(body.notice_version_id)
    if notice is None or notice.superseded_at is not None:
        raise HTTPException(409, "notice_version_superseded")

    # 2. Verify the client-reported content hash matches stored bytes for
    #    the language it claims to have shown. This is the binding between
    #    S. 5(3) (language) and S. 6(1) (informed consent).
    translation = await db.fetch_notice_translation(
        body.notice_version_id, body.language_shown
    )
    if translation is None:
        raise HTTPException(400, "unsupported_language")
    if not hmac.compare_digest(translation.content_hash, body.content_hash_shown):
        raise HTTPException(400, "content_hash_mismatch")

    # 3. Build and sign the receipt. The record and the receipt share one
    #    timestamp, so the stored evidence matches what was signed.
    granted_at = datetime.now(timezone.utc)
    pseudonym = hmac_sha256(str(body.principal_id), key=settings.pseudonym_key).hex()
    receipt = build_consent_receipt(
        principal_pseudonym=pseudonym,
        purpose_id=str(notice.purpose_id),
        notice_version_id=str(notice.notice_version_id),
        content_hash_shown=translation.content_hash,
        language_shown=body.language_shown,
        signing_key=settings.signing_key,
        granted_at=granted_at,
    )

    # 4. Insert consent_record and NOTICE_SHOWN + GRANT audit events
    #    in a single transaction.
    async with db.transaction():
        consent_id = await db.insert_consent_record(
            principal_id=body.principal_id,
            purpose_id=notice.purpose_id,
            notice_version_id=notice.notice_version_id,
            language_shown=body.language_shown,
            receipt_hash=bytes.fromhex(receipt["receipt_hash"]),
            granted_at=granted_at,
        )
        await db.append_audit_event(consent_id, "NOTICE_SHOWN",
                                    {"language": body.language_shown,
                                     "content_hash": receipt["content_hash"]})
        await db.append_audit_event(consent_id, "GRANT",
                                    {"receipt": receipt})

    return ConsentGrantResponse(consent_id=consent_id, receipt=receipt)


@router.post("/v1/consents/{consent_id}/withdraw", status_code=200)
async def withdraw_consent(
    consent_id: uuid.UUID,
    db: ConsentStore = Depends(get_store),
    settings: Settings = Depends(get_settings),
) -> ConsentWithdrawResponse:
    withdrawn_at = datetime.now(timezone.utc)
    processors = getattr(settings, "processors", [])

    # The row lock (SELECT ... FOR UPDATE via fetch_consent_record_for_update)
    # and withdrawal mutation are executed inside a single transaction to prevent
    # concurrent requests from writing duplicate WITHDRAW audit events.
    async with db.transaction():
        record = await db.fetch_consent_record_for_update(consent_id)
        if record is None:
            raise HTTPException(404, "consent_not_found")
        if record.get("status") == "withdrawn":
            raise HTTPException(409, "consent_already_withdrawn")

        await db.withdraw_consent_record(consent_id, withdrawn_at)
        await db.append_audit_event(
            consent_id,
            "WITHDRAW",
            {"withdrawn_at": withdrawn_at.isoformat(), "reason": "principal_withdrawal"},
        )
        # Section 6(6): on withdrawal the fiduciary must, within a reasonable time, cease and
        # cause its processors to cease processing, unless processing without consent is
        # required or authorised by law. Erasure (Section 8(7)) has its own carve-out for
        # retention required by law, so this fan-out instructs processors to stop, and the
        # erasure decision stays with the retention and legal-hold logic.
        for proc in processors:
            await db.record_processor_fanout(consent_id, proc)
            await db.append_audit_event(
                consent_id,
                "CEASE_PROCESSING_FANOUT",
                {"processor_id": proc, "triggered_by": "WITHDRAW", "basis": "S.6(6)"},
            )

    return ConsentWithdrawResponse(
        consent_id=consent_id,
        status="withdrawn",
        withdrawn_at=withdrawn_at,
        processors_notified=processors,
        withdrawn_consent_ids=[consent_id],
    )


@router.post("/v1/consents/withdraw", status_code=200)
async def withdraw_consent_parity(
    body: ConsentWithdrawRequest,
    db: ConsentStore = Depends(get_store),
    settings: Settings = Depends(get_settings),
) -> ConsentWithdrawResponse:
    """One-call withdrawal of every active consent for a principal and purpose.

    Section 6(4) requires that withdrawing consent be as easy as giving it. An endpoint
    cannot satisfy that on its own (the user journey has to match the grant path), but it
    removes the server-side reason for a harder withdrawal: all records are withdrawn in one
    atomic transaction with row locks.
    """
    withdrawn_at = datetime.now(timezone.utc)
    processors = getattr(settings, "processors", [])

    async with db.transaction():
        records = await db.fetch_active_consents_for_update(body.principal_id, body.purpose_id)
        if not records:
            raise HTTPException(404, "active_consent_not_found")

        withdrawn_ids = []
        for record in records:
            cid = record["consent_id"]
            await db.withdraw_consent_record(cid, withdrawn_at)
            await db.append_audit_event(
                cid,
                "WITHDRAW",
                {"withdrawn_at": withdrawn_at.isoformat(), "reason": "principal_withdrawal_parity"},
            )
            for proc in processors:
                await db.record_processor_fanout(cid, proc)
                await db.append_audit_event(
                    cid,
                    "CEASE_PROCESSING_FANOUT",
                    {"processor_id": proc, "triggered_by": "WITHDRAW", "basis": "S.6(6)"},
                )
            withdrawn_ids.append(cid)

    return ConsentWithdrawResponse(
        consent_id=withdrawn_ids[-1],
        status="withdrawn",
        withdrawn_at=withdrawn_at,
        processors_notified=processors,
        withdrawn_consent_ids=withdrawn_ids,
    )


def create_app(store: ConsentStore, settings: Settings) -> FastAPI:
    app = FastAPI(title="DPDPA consent API (reference)")
    app.include_router(router)
    app.dependency_overrides[get_store] = lambda: store
    app.dependency_overrides[get_settings] = lambda: settings
    return app
