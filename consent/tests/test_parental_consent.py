from datetime import date, datetime, timedelta, timezone

import pytest
from parental_consent import (
    ChildDataGuard,
    ChildProcessingViolation,
    GuardianRelationship,
    InMemoryParentVerifier,
    ProhibitedProcessingType,
    RejectingParentVerifier,
    StatutoryVerificationMethod,
    calculate_age,
    is_child,
)


class TestAgeAndChildStatus:
    def test_age_calculation(self):
        dob = date(2012, 5, 10)
        at = date(2026, 5, 9)
        assert calculate_age(dob, at) == 13
        at = date(2026, 5, 10)
        assert calculate_age(dob, at) == 14

    def test_is_child_boundary(self):
        dob = date(2008, 1, 1)
        assert is_child(dob, at_date=date(2025, 12, 31)) is True
        assert is_child(dob, at_date=date(2026, 1, 1)) is False
        assert is_child(dob, at_date=date(2026, 1, 2)) is False


class TestRule10VerificationAndConsent:
    def test_default_guard_fails_closed_without_explicit_verifier(self):
        """Unconfigured ChildDataGuard defaults to RejectingParentVerifier (fails closed)."""
        guard = ChildDataGuard()
        with pytest.raises(ChildProcessingViolation, match="Rule 10 verification failed"):
            guard.register_parental_consent(
                child_principal_id="c-0",
                guardian_principal_id="g-0",
                relationship=GuardianRelationship.PARENT,
                verification_method=StatutoryVerificationMethod.EXISTING_FIDUCIARY_RECORDS,
                verification_data="unconfigured_data",
                approved_purposes=["app_access"],
            )

    def test_registration_with_existing_records(self):
        guard = ChildDataGuard(verifier=InMemoryParentVerifier())
        record = guard.register_parental_consent(
            child_principal_id="child-001",
            guardian_principal_id="parent-001",
            relationship=GuardianRelationship.PARENT,
            verification_method=StatutoryVerificationMethod.EXISTING_FIDUCIARY_RECORDS,
            verification_data="fiduciary_account_ref:user_9921",
            approved_purposes=["educational_analytics", "portal_access"],
        )
        assert record.child_principal_id == "child-001"
        assert record.guardian_principal_id == "parent-001"
        assert record.verification_method == StatutoryVerificationMethod.EXISTING_FIDUCIARY_RECORDS
        assert len(record.verification_proof_hash) == 64
        assert record.is_active() is True

    def test_registration_with_authorized_entity_token(self):
        guard = ChildDataGuard(verifier=InMemoryParentVerifier())
        record = guard.register_parental_consent(
            child_principal_id="child-002",
            guardian_principal_id="guardian-002",
            relationship=GuardianRelationship.LAWFUL_GUARDIAN,
            verification_method=StatutoryVerificationMethod.AUTHORIZED_ENTITY_TOKEN,
            verification_data=b"digilocker_token_sample_payload",
            approved_purposes=["healthcare_access"],
        )
        assert record.child_principal_id == "child-002"
        assert record.relationship == GuardianRelationship.LAWFUL_GUARDIAN
        assert record.verification_method == StatutoryVerificationMethod.AUTHORIZED_ENTITY_TOKEN

    def test_failed_rule10_verification_raises_violation(self):
        guard = ChildDataGuard(verifier=RejectingParentVerifier())
        with pytest.raises(ChildProcessingViolation, match="Rule 10 verification failed"):
            guard.register_parental_consent(
                child_principal_id="child-001",
                guardian_principal_id="unverified-parent",
                relationship=GuardianRelationship.PARENT,
                verification_method=StatutoryVerificationMethod.EXISTING_FIDUCIARY_RECORDS,
                verification_data="unverified_data",
                approved_purposes=["app_access"],
            )

    def test_custom_verifier_receives_exact_parameters(self):
        recorded = {}

        class TrackingVerifier:
            def verify_adult_guardian(
                self,
                guardian_id: str,
                method: StatutoryVerificationMethod,
                verification_data: bytes | str,
            ) -> bool:
                recorded["guardian_id"] = guardian_id
                recorded["method"] = method
                recorded["data"] = verification_data
                return True

        guard = ChildDataGuard(verifier=TrackingVerifier())
        guard.register_parental_consent(
            child_principal_id="c-1",
            guardian_principal_id="g-1",
            relationship=GuardianRelationship.PARENT,
            verification_method=StatutoryVerificationMethod.AUTHORIZED_ENTITY_TOKEN,
            verification_data="digilocker_assertion",
            approved_purposes=["reading"],
        )
        assert recorded["guardian_id"] == "g-1"
        assert recorded["method"] == StatutoryVerificationMethod.AUTHORIZED_ENTITY_TOKEN
        assert recorded["data"] == "digilocker_assertion"


class TestMultiConsentAndWithdrawal:
    def test_multiple_consents_retained_per_child(self):
        guard = ChildDataGuard(verifier=InMemoryParentVerifier())
        c1 = guard.register_parental_consent(
            child_principal_id="child-10",
            guardian_principal_id="parent-10",
            relationship=GuardianRelationship.PARENT,
            verification_method=StatutoryVerificationMethod.EXISTING_FIDUCIARY_RECORDS,
            verification_data="proof-1",
            approved_purposes=["purpose_a"],
        )
        c2 = guard.register_parental_consent(
            child_principal_id="child-10",
            guardian_principal_id="parent-10",
            relationship=GuardianRelationship.PARENT,
            verification_method=StatutoryVerificationMethod.EXISTING_FIDUCIARY_RECORDS,
            verification_data="proof-2",
            approved_purposes=["purpose_b"],
        )

        assert c1.consent_id != c2.consent_id
        assert len(guard.consents["child-10"]) == 2
        dob = date(2015, 1, 1)
        assert guard.validate_processing(dob, "child-10", "purpose_a") is True
        assert guard.validate_processing(dob, "child-10", "purpose_b") is True

    def test_withdrawal_per_section_6_4(self):
        guard = ChildDataGuard(verifier=InMemoryParentVerifier())
        c1 = guard.register_parental_consent(
            child_principal_id="child-11",
            guardian_principal_id="parent-11",
            relationship=GuardianRelationship.PARENT,
            verification_method=StatutoryVerificationMethod.EXISTING_FIDUCIARY_RECORDS,
            verification_data="proof-1",
            approved_purposes=["purpose_a"],
        )
        dob = date(2015, 1, 1)
        assert guard.validate_processing(dob, "child-11", "purpose_a") is True

        # Withdraw
        ok = guard.withdraw_parental_consent(c1.consent_id)
        assert ok is True
        assert c1.withdrawn is True
        assert c1.withdrawn_at is not None

        # Subsequent validation must fail
        with pytest.raises(ChildProcessingViolation, match="Section 9\\(1\\) violation"):
            guard.validate_processing(dob, "child-11", "purpose_a")

    def test_withdrawal_unknown_consent_returns_false(self):
        guard = ChildDataGuard(verifier=InMemoryParentVerifier())
        assert guard.withdraw_parental_consent("non-existent-id") is False

    def test_expired_consent_is_not_active(self):
        guard = ChildDataGuard(verifier=InMemoryParentVerifier())
        past = datetime.now(timezone.utc) - timedelta(hours=1)
        guard.register_parental_consent(
            child_principal_id="child-12",
            guardian_principal_id="parent-12",
            relationship=GuardianRelationship.PARENT,
            verification_method=StatutoryVerificationMethod.EXISTING_FIDUCIARY_RECORDS,
            verification_data="proof-1",
            approved_purposes=["purpose_a"],
            expires_at=past,
        )
        dob = date(2015, 1, 1)
        with pytest.raises(ChildProcessingViolation, match="Section 9\\(1\\) violation"):
            guard.validate_processing(dob, "child-12", "purpose_a")


class TestSection93Prohibitions:
    @pytest.mark.parametrize(
        "prohibited",
        [
            ProhibitedProcessingType.TRACKING.value,
            ProhibitedProcessingType.BEHAVIOURAL_MONITORING.value,
            ProhibitedProcessingType.TARGETED_ADVERTISING.value,
            " tracking ",
            "TARGETED_ADVERTISING",
        ],
    )
    def test_prohibited_processing_rejected_for_child(self, prohibited):
        guard = ChildDataGuard(verifier=InMemoryParentVerifier())
        guard.register_parental_consent(
            child_principal_id="child-20",
            guardian_principal_id="parent-20",
            relationship=GuardianRelationship.PARENT,
            verification_method=StatutoryVerificationMethod.EXISTING_FIDUCIARY_RECORDS,
            verification_data="proof",
            approved_purposes=["gaming_service"],
        )
        dob = date(2014, 1, 1)
        with pytest.raises(ChildProcessingViolation, match="Section 9\\(3\\) violation"):
            guard.validate_processing(
                child_dob=dob,
                child_principal_id="child-20",
                purpose_key="gaming_service",
                activity_type=prohibited,
            )

    def test_adult_is_unaffected_by_child_prohibitions(self):
        guard = ChildDataGuard()
        adult_dob = date(1995, 1, 1)
        # Even with no consent registered and tracking activity, adults pass through Section 9 guard
        assert guard.validate_processing(
            child_dob=adult_dob,
            child_principal_id="adult-01",
            purpose_key="targeted_campaign",
            activity_type="targeted_advertising",
        ) is True


class TestStatutoryExemptions:
    def test_exempt_purpose_permits_processing_without_consent(self):
        # Section 9(4)-(5), Rule 12 & Fourth Schedule (e.g. clinical care / child safety)
        guard = ChildDataGuard(exempt_purposes={"emergency_medical_triage", "child_safety_monitoring"})
        child_dob = date(2015, 1, 1)

        # Processing permitted even without prior consent
        assert guard.validate_processing(
            child_dob=child_dob,
            child_principal_id="child-emergency-01",
            purpose_key="emergency_medical_triage",
        ) is True

    def test_exempt_purpose_permits_monitoring_for_safety(self):
        guard = ChildDataGuard(exempt_purposes={"school_bus_telematics"})
        child_dob = date(2015, 1, 1)

        assert guard.validate_processing(
            child_dob=child_dob,
            child_principal_id="child-safety-01",
            purpose_key="school_bus_telematics",
            activity_type="tracking",
        ) is True

    def test_exempt_purpose_for_educational_curriculum(self):
        # Fourth Schedule: educational institutions for education delivery purposes
        guard = ChildDataGuard(exempt_purposes={"educational_curriculum_delivery"})
        child_dob = date(2015, 1, 1)

        assert guard.validate_processing(
            child_dob=child_dob,
            child_principal_id="student-01",
            purpose_key="educational_curriculum_delivery",
        ) is True
