"""
parental_consent.py

Implements Verifiable Parental Consent (VPC) and Child Data Protection safeguards
mandated by DPDPA Section 9 and DPDP Rules, 2025 Rule 10, Rule 12 and the Fourth Schedule.

Statutory Scope & Context:
  - Section 9(1) & Rule 10(1): The Data Fiduciary must confirm that the person giving
    consent as the parent is an identifiable adult. Rule 10(1) allows that to rest on:
      (a) reliable details of identity and age already available with the fiduciary; or
      (b) details of identity and age voluntarily provided (i) by the individual, or
          (ii) through a virtual token mapped to such details, issued by an authorised
          entity (Rule 10(2) names Digital Locker service providers among these).
    Only the token in (b)(ii) comes from an authorised entity; (b)(i) details may be
    volunteered by the individual.
  - Section 9(2): no processing "likely to cause any detrimental effect on the well-being
    of a child". Rule 12 disapplies only 9(1) and 9(3); nothing disapplies 9(2). This module
    enforces 9(2) through the `detrimental_effect` flag on `validate_processing`.
  - Section 9(3): no tracking or behavioural monitoring of children, and no targeted
    advertising directed at children.
  - Section 9(4), Rule 12 & Fourth Schedule: 9(1) and 9(3) do not apply to the classes of
    Data Fiduciary in Part A (clinical establishments, educational institutions, crèches,
    transport providers and others) ONLY for the conditioned processing listed against each
    (for example, an educational institution: "restricted to tracking and behavioural
    monitoring for the educational activities of such institution or in the interests of
    safety of children"), and to the purposes in Part B under their conditions. The
    exemption attaches to the class plus the condition, never to a purpose alone.
    Section 9(5) is a different mechanism (an age above which a notified fiduciary is
    exempt) and is not modelled here.
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
    EXISTING_FIDUCIARY_RECORDS = "existing_fiduciary_records"  # Rule 10(1)(a)
    VOLUNTARY_DETAILS = "voluntary_details"  # Rule 10(1)(b)(i): details provided by the individual
    AUTHORIZED_ENTITY_TOKEN = "authorized_entity_token"  # Rule 10(1)(b)(ii), e.g. a Digital Locker token # noqa: S105


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
        # Rule 12 & Fourth Schedule exemptions. Each key must name the CONDITIONED processing of
        # a Schedule entry that applies to this fiduciary's class (for example
        # "safety_monitoring" for an educational institution under Part A item 3), not a
        # general purpose; the Schedule exempts a class for a condition, never a purpose alone.
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
        """Checks if a conditioned processing key is exempt under Rule 12 and the Fourth Schedule.

        Rule 12 disapplies Section 9(1) (verifiable parental consent) and 9(3) (tracking,
        behavioural monitoring, targeted advertising) for the Schedule's classes, only for the
        processing listed against each class. It never disapplies Section 9(2).
        """
        return purpose_key in self.exempt_purposes

    def validate_processing(
        self,
        child_dob: date,
        child_principal_id: str,
        purpose_key: str,
        activity_type: str | None = None,
        now: datetime | None = None,
        detrimental_effect: bool = False,
    ) -> bool:
        """Validates whether processing is permitted under Section 9, checking consent and exemptions.

        `detrimental_effect` is the caller's own assessment that the processing is likely to
        cause a detrimental effect on the child's well-being. Section 9(2) forbids that
        outright and no exemption reaches it, so it is checked before anything else.
        """
        current_time = now or datetime.now(timezone.utc)
        current_date = current_time.date()

        # A person who has completed eighteen years is not a child (Section 2(f)).
        if not is_child(child_dob, current_date):
            return True

        # Section 9(2): never waived, not by consent and not by Rule 12.
        if detrimental_effect:
            raise ChildProcessingViolation(
                "DPDPA Section 9(2) violation: processing likely to cause a detrimental effect "
                "on the well-being of a child is prohibited; no exemption or consent applies."
            )

        # Rule 12 / Fourth Schedule: the class-plus-condition exemptions configured for this fiduciary
        if self.is_exempt(purpose_key):
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
