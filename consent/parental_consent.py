"""
parental_consent.py

Implements Verifiable Parental Consent (VPC) and Child Data Protection safeguards
mandated by DPDPA Section 9 and DPDP Rules, 2025 Rule 10, Rule 12 and the Fourth Schedule.

Statutory Scope & Context:
  - Section 9(1) & Rule 10: The Data Fiduciary must confirm that the parent or lawful
    guardian is an identifiable adult before obtaining verifiable consent. Under Rule 10,
    confirmation is obtained via:
      (a) Reliable identity and age details already held by the fiduciary; or
      (b) Details or a virtual token issued by an authorized entity (e.g. DigiLocker).
  - Section 9(2): Absolute prohibition on processing causing a detrimental effect on
    the well-being of the child. Statutory exemptions under Rule 12 NEVER waive Section 9(2).
  - Section 9(3): Prohibitions on tracking, behavioural monitoring, and targeted advertising.
  - Section 9(4)–(5), Rule 12 & Fourth Schedule: Statutory exemptions for notified classes of
    fiduciaries (e.g., clinical establishments, educational institutions, crèches) exempting
    them from Section 9(1) and 9(3) strictly for the specific processing purposes listed against
    them in the Fourth Schedule.
  - Section 9 & Rule 11 Scope Distinction: Section 9 also applies to processing personal data of
    persons with disability who have a lawful guardian, governed by the verification procedure
    under Rule 11. That workflow is out of scope for this module, which focuses on child data
    protection under Rule 10.
"""
import uuid
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from enum import Enum
from hashlib import sha256
from typing import Protocol


class GuardianRelationship(Enum):
    PARENT = "parent"
    LAWFUL_GUARDIAN = "lawful_guardian"


class StatutoryVerificationMethod(Enum):
    """Methods prescribed by Rule 10 to confirm the parent is an identifiable adult."""
    EXISTING_FIDUCIARY_RECORDS = "existing_fiduciary_records"  # Rule 10(a)
    AUTHORIZED_ENTITY_TOKEN = "authorized_entity_token"  # Rule 10(b), e.g., DigiLocker # noqa: S105


class ProhibitedProcessingType(Enum):
    TRACKING = "tracking"
    BEHAVIOURAL_MONITORING = "behavioural_monitoring"
    TARGETED_ADVERTISING = "targeted_advertising"


class ChildProcessingViolation(Exception):
    """Raised when an operation violates Section 9 child protection safeguards."""
    pass


class ParentVerifier(Protocol):
    """Interface to confirm that the parent/guardian is an identifiable adult (Rule 10)."""
    def verify_adult_guardian(
        self,
        guardian_id: str,
        method: StatutoryVerificationMethod,
        verification_data: bytes | str,
    ) -> bool: ...


@dataclass
class RejectingParentVerifier:
    """Fail-closed verifier that always rejects. Default for ChildDataGuard to ensure
    callers explicitly configure an authorized identity verification provider."""

    def verify_adult_guardian(
        self,
        guardian_id: str,
        method: StatutoryVerificationMethod,
        verification_data: bytes | str,
    ) -> bool:
        return False


@dataclass
class InMemoryParentVerifier:
    """Reference verifier for tests and local development."""
    verified_guardians: set[str] = field(default_factory=set)

    def verify_adult_guardian(
        self,
        guardian_id: str,
        method: StatutoryVerificationMethod,
        verification_data: bytes | str,
    ) -> bool:
        # Accepts if guardian is known or verification data is provided
        return bool(guardian_id in self.verified_guardians or verification_data)


def calculate_age(dob: date, at_date: date | None = None) -> int:
    at = at_date or datetime.now(timezone.utc).date()
    return at.year - dob.year - ((at.month, at.day) < (dob.month, dob.day))


def is_child(dob: date, at_date: date | None = None) -> bool:
    """DPDPA Section 2(f): 'child' means an individual who has not completed the age of eighteen years."""
    return calculate_age(dob, at_date) < 18


@dataclass
class ParentalConsentRecord:
    consent_id: str
    child_principal_id: str
    guardian_principal_id: str
    relationship: GuardianRelationship
    verification_method: StatutoryVerificationMethod
    verification_proof_hash: str
    approved_purposes: list[str]
    verified_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime | None = None
    withdrawn: bool = False
    withdrawn_at: datetime | None = None

    def is_active(self, now: datetime | None = None) -> bool:
        if self.withdrawn:
            return False
        current = now or datetime.now(timezone.utc)
        if self.expires_at and current >= self.expires_at:
            return False
        return True


class ChildDataGuard:
    """Enforces Section 9 child data protection rules, verifiable consent, and statutory exemptions."""

    def __init__(
        self,
        verifier: ParentVerifier | None = None,
        exempt_purposes: set[str] | None = None,
    ):
        # Default to fail-closed verifier so unconfigured guards never grant unverified consent
        self.verifier = verifier or RejectingParentVerifier()
        # Section 9(4)-(5), Rule 12 & Fourth Schedule exemptions (purpose-based only, e.g. clinical/educational)
        self.exempt_purposes = set(exempt_purposes or set())
        # Keyed by child_principal_id -> list of consent records (supporting multiple consents over time)
        self.consents: dict[str, list[ParentalConsentRecord]] = {}

    def register_parental_consent(
        self,
        child_principal_id: str,
        guardian_principal_id: str,
        relationship: GuardianRelationship,
        verification_method: StatutoryVerificationMethod,
        verification_data: bytes | str,
        approved_purposes: list[str],
        expires_at: datetime | None = None,
    ) -> ParentalConsentRecord:
        """Confirms parent is an identifiable adult (Rule 10) and registers consent."""
        is_verified = self.verifier.verify_adult_guardian(
            guardian_id=guardian_principal_id,
            method=verification_method,
            verification_data=verification_data,
        )
        if not is_verified:
            raise ChildProcessingViolation(
                f"Rule 10 verification failed: Guardian '{guardian_principal_id}' could not be "
                f"confirmed as an identifiable adult via {verification_method.value}."
            )

        proof_bytes = verification_data.encode("utf-8") if isinstance(verification_data, str) else verification_data
        proof_hash = sha256(proof_bytes).hexdigest()

        record = ParentalConsentRecord(
            consent_id=str(uuid.uuid4()),
            child_principal_id=child_principal_id,
            guardian_principal_id=guardian_principal_id,
            relationship=relationship,
            verification_method=verification_method,
            verification_proof_hash=proof_hash,
            approved_purposes=approved_purposes,
            verified_at=datetime.now(timezone.utc),
            expires_at=expires_at,
        )

        if child_principal_id not in self.consents:
            self.consents[child_principal_id] = []
        self.consents[child_principal_id].append(record)
        return record

    def withdraw_parental_consent(self, consent_id: str) -> bool:
        """Withdraws parental consent per Section 6(4)."""
        now = datetime.now(timezone.utc)
        for consent_list in self.consents.values():
            for consent in consent_list:
                if consent.consent_id == consent_id:
                    consent.withdrawn = True
                    consent.withdrawn_at = now
                    return True
        return False

    def is_exempt(self, purpose_key: str) -> bool:
        """Checks if purpose is exempt under Section 9(4)-(5), Rule 12 & Fourth Schedule.

        Note: Statutory exemptions relieve the fiduciary from Section 9(1) verifiable consent
        and Section 9(3) tracking/ad restrictions strictly for the listed purposes (e.g., healthcare,
        education, safety). Exemptions NEVER waive Section 9(2) (detrimental effects on child).
        """
        return purpose_key in self.exempt_purposes

    def validate_processing(
        self,
        child_dob: date,
        child_principal_id: str,
        purpose_key: str,
        activity_type: str | None = None,
        now: datetime | None = None,
    ) -> bool:
        """Validates whether processing is permitted under Section 9, checking consent and exemptions."""
        current_time = now or datetime.now(timezone.utc)
        current_date = current_time.date()

        # Adults (> 18) are outside Section 9 child constraints
        if not is_child(child_dob, current_date):
            return True

        # Check Fourth Schedule / Rule 12 statutory exemptions
        if self.is_exempt(purpose_key):
            # Exempt purposes (e.g. educational safety tracking, medical clinical care) are permitted
            return True

        # Check Section 9(3) statutory prohibitions
        if activity_type:
            normalized_activity = activity_type.lower().strip()
            prohibited_types = {p.value for p in ProhibitedProcessingType}
            if normalized_activity in prohibited_types:
                raise ChildProcessingViolation(
                    f"DPDPA Section 9(3) violation: processing of type '{activity_type}' "
                    f"is strictly prohibited for children."
                )

        # Check Section 9(1) verifiable parental consent
        child_consents = self.consents.get(child_principal_id, [])
        active_consent_for_purpose = any(
            c.is_active(current_time) and purpose_key in c.approved_purposes
            for c in child_consents
        )

        if not active_consent_for_purpose:
            raise ChildProcessingViolation(
                f"DPDPA Section 9(1) violation: No active verifiable parental consent "
                f"registered for child '{child_principal_id}' and purpose '{purpose_key}'."
            )

        return True
