# Architectural pattern: Zero-knowledge consent routing
#
# The router is the one from the article. The record types and the two
# collaborator interfaces are added so it runs; plug in your own ledger
# (see ledger.sql) and fiduciary transport.
from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
from typing import Protocol


@dataclass(frozen=True)
class ConsentRecord:
    principal_id: str  # the CM's own account identifier for the Data Principal
    fiduciary_id: str
    purpose_id: str
    action: str
    timestamp: datetime
    consent_token_hash: str


@dataclass(frozen=True)
class ShareRecord:
    principal_id: str
    source: str
    target: str
    timestamp: datetime
    payload_hash: str


class ConsentStore(Protocol):
    def persist(self, record: ConsentRecord | ShareRecord) -> None: ...


class FiduciaryGateway(Protocol):
    def forward(self, fiduciary_id: str, encrypted_token: bytes) -> None: ...
    def transfer(self, target: str, encrypted_payload: bytes) -> None: ...


class ConsentManagerRouter:
    """
    Routes consent decisions and data-sharing instructions between
    Data Principals and Data Fiduciaries without accessing personal data.
    Implements First Schedule, Part B, Item 2.
    """

    def __init__(self, consent_store: ConsentStore, fiduciary_gateway: FiduciaryGateway):
        self.consent_store = consent_store
        self.fiduciary_gateway = fiduciary_gateway

    def route_consent_grant(
        self,
        principal_id: str,
        fiduciary_id: str,
        purpose_id: str,
        encrypted_consent_token: bytes  # Encrypted by Data Principal's key
    ) -> ConsentRecord:
        # CM records the consent metadata -- NOT the personal data
        record = ConsentRecord(
            principal_id=principal_id,
            fiduciary_id=fiduciary_id,
            purpose_id=purpose_id,
            action="GRANT",
            timestamp=datetime.now(timezone.utc),
            # Store encrypted token for audit -- CM cannot decrypt
            consent_token_hash=sha256(encrypted_consent_token).hexdigest()
        )
        self.consent_store.persist(record)

        # Forward the encrypted token to the Data Fiduciary
        # CM never sees the decrypted consent payload
        self.fiduciary_gateway.forward(
            fiduciary_id=fiduciary_id,
            encrypted_token=encrypted_consent_token
        )
        return record

    def route_consent_withdraw(
        self,
        principal_id: str,
        fiduciary_id: str,
        purpose_id: str,
        encrypted_withdrawal_token: bytes,
    ) -> ConsentRecord:
        """Routes a consent withdrawal from Data Principal to Data Fiduciary
        without accessing personal data, per DPDPA Section 6(7)."""
        record = ConsentRecord(
            principal_id=principal_id,
            fiduciary_id=fiduciary_id,
            purpose_id=purpose_id,
            action="WITHDRAW",
            timestamp=datetime.now(timezone.utc),
            consent_token_hash=sha256(encrypted_withdrawal_token).hexdigest(),
        )
        self.consent_store.persist(record)

        self.fiduciary_gateway.forward(
            fiduciary_id=fiduciary_id,
            encrypted_token=encrypted_withdrawal_token,
        )
        return record

    def route_data_share(
        self,
        principal_id: str,
        source_fiduciary_id: str,
        target_fiduciary_id: str,
        encrypted_payload: bytes  # E2E encrypted -- CM cannot read
    ) -> ShareRecord:
        # CM records the sharing event metadata
        share_record = ShareRecord(
            principal_id=principal_id,
            source=source_fiduciary_id,
            target=target_fiduciary_id,
            timestamp=datetime.now(timezone.utc),
            payload_hash=sha256(encrypted_payload).hexdigest()
        )
        self.consent_store.persist(share_record)

        # Route without decrypting
        self.fiduciary_gateway.transfer(
            target=target_fiduciary_id,
            encrypted_payload=encrypted_payload
        )
        return share_record
