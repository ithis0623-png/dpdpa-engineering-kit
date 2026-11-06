from datetime import datetime, timedelta, timezone

import pytest
from grievance_service import (
    DPBI_COMPLAINT_ADVISORY,
    DPDPAGrievanceService,
    GrievanceCategory,
    GrievanceStatus,
    InMemoryAuditSink,
)


class TestGrievanceServiceInitialization:
    def test_sla_within_statutory_ceiling(self):
        service = DPDPAGrievanceService(sla_days=30)
        assert service.sla_days == 30

        # Maximum statutory ceiling is 90 days under Rule 14(3)
        service_max = DPDPAGrievanceService(sla_days=90)
        assert service_max.sla_days == 90

    @pytest.mark.parametrize("invalid_days", [-10, 0, 91, 120])
    def test_sla_invalid_range_rejected(self, invalid_days):
        with pytest.raises(ValueError, match="is invalid; must be between 1 and"):
            DPDPAGrievanceService(sla_days=invalid_days)


class TestGrievanceRegistrationAndLifecycle:
    def test_registration_with_auto_acknowledge(self):
        audit = InMemoryAuditSink()
        service = DPDPAGrievanceService(audit=audit, sla_days=30)
        now = datetime(2026, 5, 1, 10, 0, tzinfo=timezone.utc)

        ticket = service.register_grievance(
            principal_id="principal-100",
            category=GrievanceCategory.CONSENT_VIOLATION,
            description="Consent was revoked but marketing SMS continues.",
            created_at=now,
            auto_acknowledge=True,
        )

        assert ticket.ticket_id.startswith("GRV-2026-")
        assert ticket.principal_id == "principal-100"
        assert ticket.category == GrievanceCategory.CONSENT_VIOLATION
        assert ticket.status == GrievanceStatus.ACKNOWLEDGED
        assert ticket.acknowledged_at == now
        assert ticket.sla_due_at == now + timedelta(days=30)
        assert ticket.is_closed is False
        assert "Section 13(3)" in ticket.dpbi_appeal_notice
        assert "Section 27(1)" not in ticket.dpbi_appeal_notice

        assert len(audit.events) == 1
        assert audit.events[0]["event"] == "grievance_registered"

    def test_registration_manual_acknowledge(self):
        service = DPDPAGrievanceService(sla_days=30)
        now = datetime(2026, 5, 1, 10, 0, tzinfo=timezone.utc)

        ticket = service.register_grievance(
            principal_id="principal-101",
            category="rights_unfulfilled",
            description="Erasure request not completed.",
            created_at=now,
            auto_acknowledge=False,
        )

        assert ticket.status == GrievanceStatus.SUBMITTED
        assert ticket.acknowledged_at is None

        # Manually acknowledge
        ack_ticket = service.acknowledge_grievance(ticket.ticket_id)
        assert ack_ticket.status == GrievanceStatus.ACKNOWLEDGED
        assert ack_ticket.acknowledged_at is not None

    def test_empty_description_raises(self):
        service = DPDPAGrievanceService()
        with pytest.raises(ValueError, match="cannot be empty"):
            service.register_grievance("p-1", GrievanceCategory.SECURITY_BREACH, "   ")


class TestEscalationMechanism:
    def test_escalation_default_grievance_officer(self):
        audit = InMemoryAuditSink()
        service = DPDPAGrievanceService(audit=audit)
        ticket = service.register_grievance(
            principal_id="p-200",
            category=GrievanceCategory.SECURITY_BREACH,
            description="Potential unauthorized access to medical records.",
        )

        escalated = service.escalate(ticket.ticket_id, reason="Complex cross-system breach investigation")
        assert escalated.status == GrievanceStatus.ESCALATED
        assert escalated.escalated_to == "Grievance Officer"
        assert escalated.escalation_reason == "Complex cross-system breach investigation"
        assert escalated.escalated_at is not None

        esc_events = [e for e in audit.events if e["event"] == "grievance_escalated"]
        assert len(esc_events) == 1
        assert esc_events[0]["target_role"] == "Grievance Officer"

    def test_escalation_to_dpo_for_sdf(self):
        service = DPDPAGrievanceService()
        ticket = service.register_grievance(
            principal_id="p-201",
            category=GrievanceCategory.CHILD_DATA_PROTECTION,
            description="Targeted ad shown to child user.",
        )

        escalated = service.escalate(
            ticket.ticket_id,
            reason="Statutory child protection violation review",
            target_role="Data Protection Officer",
        )
        assert escalated.status == GrievanceStatus.ESCALATED
        assert escalated.escalated_to == "Data Protection Officer"


class TestResolutionAndRejection:
    def test_resolve_grievance(self):
        audit = InMemoryAuditSink()
        service = DPDPAGrievanceService(audit=audit)
        ticket = service.register_grievance(
            principal_id="p-300",
            category=GrievanceCategory.CONSENT_VIOLATION,
            description="Opt-out ignored by downstream newsletter.",
        )

        resolved = service.resolve_grievance(
            ticket.ticket_id,
            resolution_summary="Suppression list synchronized across all delivery nodes.",
        )
        assert resolved.status == GrievanceStatus.RESOLVED
        assert resolved.resolution_summary == "Suppression list synchronized across all delivery nodes."
        assert resolved.resolved_at is not None
        assert resolved.is_closed is True

        res_events = [e for e in audit.events if e["event"] == "grievance_resolved"]
        assert len(res_events) == 1
        assert res_events[0]["sla_breached"] is False

    def test_reject_grievance(self):
        audit = InMemoryAuditSink()
        service = DPDPAGrievanceService(audit=audit)
        ticket = service.register_grievance(
            principal_id="p-301",
            category=GrievanceCategory.RIGHTS_UNFULFILLED,
            description="Duplicate ticket regarding already-processed erasure.",
        )

        rejected = service.reject_grievance(
            ticket.ticket_id,
            rejection_reason="Duplicate request; erasure already executed under ticket GRV-2026-1234.",
        )
        assert rejected.status == GrievanceStatus.REJECTED
        assert rejected.rejection_reason.startswith("Duplicate request")
        assert rejected.rejected_at is not None
        assert rejected.is_closed is True

    def test_cannot_modify_closed_ticket(self):
        service = DPDPAGrievanceService()
        ticket = service.register_grievance("p-302", GrievanceCategory.GENERAL_PROCESSING, "test")
        service.resolve_grievance(ticket.ticket_id, "resolved")

        with pytest.raises(ValueError, match="already closed"):
            service.resolve_grievance(ticket.ticket_id, "another resolution")

        with pytest.raises(ValueError, match="already closed"):
            service.reject_grievance(ticket.ticket_id, "rejecting after resolve")

        with pytest.raises(ValueError, match="closed ticket"):
            service.escalate(ticket.ticket_id, "escalate closed")


class TestSLATrackingAndBugFixes:
    def test_rejected_ticket_within_sla_is_not_breached(self):
        """Fix verification: check_sla_status previously reported rejected tickets as breached."""
        service = DPDPAGrievanceService(sla_days=30)
        start = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
        ticket = service.register_grievance(
            principal_id="p-400",
            category=GrievanceCategory.GENERAL_PROCESSING,
            description="Inquiry about general data retention schedule.",
            created_at=start,
        )

        # Rejected after 5 days (well within 30-day SLA)
        service.reject_grievance(
            ticket.ticket_id,
            "Non-actionable grievance; policy available publicly.",
            rejected_at=start + timedelta(days=5),
        )

        # Check SLA status at 45 days (past SLA due date)
        check_time = start + timedelta(days=45)
        sla_status = service.check_sla_status(ticket.ticket_id, now=check_time)

        assert sla_status["is_closed"] is True
        assert sla_status["status"] == "rejected"
        assert sla_status["sla_breached"] is False
        assert sla_status["remaining_days"] == 0

    def test_resolved_ticket_within_sla_is_not_breached(self):
        service = DPDPAGrievanceService(sla_days=30)
        start = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
        ticket = service.register_grievance(
            principal_id="p-401",
            category=GrievanceCategory.CONSENT_VIOLATION,
            description="Marketing opt out.",
            created_at=start,
        )

        # Resolved after 10 days
        service.resolve_grievance(
            ticket.ticket_id,
            "Opt-out processed.",
            resolved_at=start + timedelta(days=10),
        )

        # Check SLA status at 60 days
        check_time = start + timedelta(days=60)
        sla_status = service.check_sla_status(ticket.ticket_id, now=check_time)

        assert sla_status["is_closed"] is True
        assert sla_status["status"] == "resolved"
        assert sla_status["sla_breached"] is False

    def test_resolved_ticket_after_sla_is_breached(self):
        service = DPDPAGrievanceService(sla_days=30)
        start = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
        ticket = service.register_grievance(
            principal_id="p-402",
            category=GrievanceCategory.CONSENT_VIOLATION,
            description="Consent issue.",
            created_at=start,
        )

        # Force resolved_at after due date
        ticket.resolved_at = start + timedelta(days=35)
        ticket.status = GrievanceStatus.RESOLVED

        sla_status = service.check_sla_status(ticket.ticket_id)
        assert sla_status["sla_breached"] is True

    def test_open_ticket_sla_tracking(self):
        service = DPDPAGrievanceService(sla_days=30)
        start = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
        ticket = service.register_grievance(
            principal_id="p-403",
            category=GrievanceCategory.RIGHTS_UNFULFILLED,
            description="Correction pending.",
            created_at=start,
        )

        # Day 10: 20 days remaining, not breached
        status_day_10 = service.check_sla_status(ticket.ticket_id, now=start + timedelta(days=10))
        assert status_day_10["sla_breached"] is False
        assert status_day_10["remaining_days"] == 20

        # Day 35: overdue, breached
        status_day_35 = service.check_sla_status(ticket.ticket_id, now=start + timedelta(days=35))
        assert status_day_35["sla_breached"] is True
        assert status_day_35["remaining_days"] == 0


def test_statutory_appeal_advisory_text():
    assert "Section 13(3)" in DPBI_COMPLAINT_ADVISORY
    assert "Section 27(1)" not in DPBI_COMPLAINT_ADVISORY
    assert "exhausted" in DPBI_COMPLAINT_ADVISORY.lower() or "utilized" in DPBI_COMPLAINT_ADVISORY.lower()
