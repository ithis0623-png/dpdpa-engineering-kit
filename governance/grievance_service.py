"""
grievance_service.py

Implements the statutory Grievance Redressal Mechanism required by DPDPA Section 13
and DPDP Rules, 2025 Rule 14.

Statutory Obligations & Scope:
  - Section 13(1) & Rule 14(1): Data Fiduciaries and Consent Managers must provide
    readily available means of grievance redressal to Data Principals.
  - Section 13(2) & Rule 14(3): The fiduciary must respond within the period it publishes,
    which must not exceed ninety (90) days. Any shorter target (e.g., 30 days) operates
    as an internal operational SLA within that statutory ceiling.
  - Section 13(3): Exhaustion requirement. The Data Principal must first exhaust the
    fiduciary's grievance redressal mechanism before approaching the Data Protection
    Board of India (DPBI). Resolution and response notices must inform the principal
    of this conditional right of complaint under Section 13(3).
  - Escalation: While Significant Data Fiduciaries (SDFs) must appoint a Data Protection
    Officer (DPO) under Section 10(2)(a), other fiduciaries designate an internal Grievance
    Officer or privacy lead. Escalation supports configurable owners.
"""
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Protocol

STATUTORY_CEILING_DAYS = 90
DEFAULT_INTERNAL_SLA_DAYS = 30

DPBI_COMPLAINT_ADVISORY = (
    "In accordance with Section 13(3) of the Digital Personal Data Protection Act, 2023, "
    "having utilized the Data Fiduciary's grievance redressal mechanism, if you are not "
    "satisfied with this resolution or have not received a response within the prescribed "
    "period, you may register a complaint with the Data Protection Board of India (DPBI)."
)


class GrievanceCategory(Enum):
    CONSENT_VIOLATION = "consent_violation"
    RIGHTS_UNFULFILLED = "rights_unfulfilled"
    SECURITY_BREACH = "security_breach"
    CHILD_DATA_PROTECTION = "child_data_protection"
    CROSS_BORDER_TRANSFER = "cross_border_transfer"
    GENERAL_PROCESSING = "general_processing"


class GrievanceStatus(Enum):
    SUBMITTED = "submitted"
    ACKNOWLEDGED = "acknowledged"
    IN_INVESTIGATION = "in_investigation"
    ESCALATED = "escalated"
    RESOLVED = "resolved"
    REJECTED = "rejected"


@dataclass
class GrievanceTicket:
    ticket_id: str
    principal_id: str
    category: GrievanceCategory
    description: str
    status: GrievanceStatus
    created_at: datetime
    sla_due_at: datetime
    acknowledged_at: datetime | None = None
    resolution_summary: str | None = None
    resolved_at: datetime | None = None
    rejection_reason: str | None = None
    rejected_at: datetime | None = None
    escalated_to: str | None = None
    escalated_at: datetime | None = None
    escalation_reason: str | None = None
    dpbi_appeal_notice: str = DPBI_COMPLAINT_ADVISORY

    @property
    def is_closed(self) -> bool:
        return self.status in {GrievanceStatus.RESOLVED, GrievanceStatus.REJECTED}


class AuditSink(Protocol):
    def write(self, event: dict) -> None: ...


@dataclass
class InMemoryAuditSink:
    events: list[dict] = field(default_factory=list)

    def write(self, event: dict) -> None:
        self.events.append(event)


class DPDPAGrievanceService:
    """Manages statutory grievance intake, SLA enforcement, and escalation."""

    def __init__(
        self,
        audit: AuditSink | None = None,
        sla_days: int = DEFAULT_INTERNAL_SLA_DAYS,
    ):
        if sla_days > STATUTORY_CEILING_DAYS:
            raise ValueError(
                f"SLA of {sla_days} days exceeds the Rule 14(3) statutory ceiling "
                f"of {STATUTORY_CEILING_DAYS} days."
            )
        self.audit = audit or InMemoryAuditSink()
        self.sla_days = sla_days
        self.tickets: dict[str, GrievanceTicket] = {}

    def register_grievance(
        self,
        principal_id: str,
        category: GrievanceCategory | str,
        description: str,
        created_at: datetime | None = None,
        auto_acknowledge: bool = True,
    ) -> GrievanceTicket:
        """Registers a grievance from a Data Principal.

        Note: Rule 14(1) requires a readily accessible grievance redressal mechanism.
        Internal SLA defaults to 30 days, within Rule 14(3)'s 90-day ceiling.
        """
        if not description.strip():
            raise ValueError("Grievance description cannot be empty")

        now = created_at or datetime.now(timezone.utc)
        cat_enum = category if isinstance(category, GrievanceCategory) else GrievanceCategory(category)
        ticket_id = f"GRV-{now.year}-{uuid.uuid4().hex[:8].upper()}"

        status = GrievanceStatus.ACKNOWLEDGED if auto_acknowledge else GrievanceStatus.SUBMITTED
        acknowledged_at = now if auto_acknowledge else None

        ticket = GrievanceTicket(
            ticket_id=ticket_id,
            principal_id=principal_id,
            category=cat_enum,
            description=description,
            status=status,
            created_at=now,
            acknowledged_at=acknowledged_at,
            sla_due_at=now + timedelta(days=self.sla_days),
        )
        self.tickets[ticket_id] = ticket

        self.audit.write({
            "event": "grievance_registered",
            "ticket_id": ticket_id,
            "principal_id": principal_id,
            "category": cat_enum.value,
            "sla_due_at": ticket.sla_due_at.isoformat(),
            "at": now.isoformat(),
        })

        return ticket

    def acknowledge_grievance(self, ticket_id: str) -> GrievanceTicket:
        """Acknowledges a submitted ticket."""
        ticket = self._get_ticket(ticket_id)
        if ticket.is_closed:
            raise ValueError(f"Cannot acknowledge closed ticket '{ticket_id}'")

        now = datetime.now(timezone.utc)
        ticket.status = GrievanceStatus.ACKNOWLEDGED
        ticket.acknowledged_at = now

        self.audit.write({
            "event": "grievance_acknowledged",
            "ticket_id": ticket_id,
            "principal_id": ticket.principal_id,
            "at": now.isoformat(),
        })
        return ticket

    def escalate(
        self,
        ticket_id: str,
        reason: str,
        target_role: str = "Grievance Officer",
    ) -> GrievanceTicket:
        """Escalates a ticket to a designated officer (e.g. DPO for SDFs, or Grievance Officer)."""
        ticket = self._get_ticket(ticket_id)
        if ticket.is_closed:
            raise ValueError(f"Cannot escalate closed ticket '{ticket_id}'")

        now = datetime.now(timezone.utc)
        ticket.status = GrievanceStatus.ESCALATED
        ticket.escalated_to = target_role
        ticket.escalated_at = now
        ticket.escalation_reason = reason

        self.audit.write({
            "event": "grievance_escalated",
            "ticket_id": ticket_id,
            "principal_id": ticket.principal_id,
            "target_role": target_role,
            "reason": reason,
            "at": now.isoformat(),
        })
        return ticket

    def resolve_grievance(
        self,
        ticket_id: str,
        resolution_summary: str,
        resolved_at: datetime | None = None,
    ) -> GrievanceTicket:
        """Resolves a grievance, attaching the resolution and Section 13(3) advisory."""
        if not resolution_summary.strip():
            raise ValueError("Resolution summary cannot be empty")

        ticket = self._get_ticket(ticket_id)
        if ticket.is_closed:
            raise ValueError(f"Ticket '{ticket_id}' is already closed")

        now = resolved_at or datetime.now(timezone.utc)
        ticket.status = GrievanceStatus.RESOLVED
        ticket.resolution_summary = resolution_summary
        ticket.resolved_at = now

        self.audit.write({
            "event": "grievance_resolved",
            "ticket_id": ticket_id,
            "principal_id": ticket.principal_id,
            "sla_breached": now > ticket.sla_due_at,
            "at": now.isoformat(),
        })
        return ticket

    def reject_grievance(
        self,
        ticket_id: str,
        rejection_reason: str,
        rejected_at: datetime | None = None,
    ) -> GrievanceTicket:
        """Rejects an ineligible or duplicate grievance with statutory advisory."""
        if not rejection_reason.strip():
            raise ValueError("Rejection reason cannot be empty")

        ticket = self._get_ticket(ticket_id)
        if ticket.is_closed:
            raise ValueError(f"Ticket '{ticket_id}' is already closed")

        now = rejected_at or datetime.now(timezone.utc)
        ticket.status = GrievanceStatus.REJECTED
        ticket.rejection_reason = rejection_reason
        ticket.rejected_at = now

        self.audit.write({
            "event": "grievance_rejected",
            "ticket_id": ticket_id,
            "principal_id": ticket.principal_id,
            "sla_breached": now > ticket.sla_due_at,
            "at": now.isoformat(),
        })
        return ticket

    def check_sla_status(self, ticket_id: str, now: datetime | None = None) -> dict:
        """Evaluates SLA health.

        Closed tickets (RESOLVED or REJECTED) report breached only if they were
        closed after the SLA due date.
        """
        ticket = self._get_ticket(ticket_id)
        current = now or datetime.now(timezone.utc)

        if ticket.is_closed:
            closed_at = ticket.resolved_at or ticket.rejected_at or current
            breached = closed_at > ticket.sla_due_at
            remaining_days = 0
        else:
            breached = current > ticket.sla_due_at
            remaining_seconds = max(0.0, (ticket.sla_due_at - current).total_seconds())
            remaining_days = int(remaining_seconds // 86400)

        return {
            "ticket_id": ticket_id,
            "status": ticket.status.value,
            "sla_due_at": ticket.sla_due_at.isoformat(),
            "sla_breached": breached,
            "remaining_days": remaining_days,
            "is_closed": ticket.is_closed,
        }

    def _get_ticket(self, ticket_id: str) -> GrievanceTicket:
        if ticket_id not in self.tickets:
            raise KeyError(f"Grievance ticket '{ticket_id}' not found")
        return self.tickets[ticket_id]
