"""
notification_formatter.py

Implements statutory personal data breach intimations under DPDPA Section 8(6)
and DPDP Rules, 2025 Rule 7 (as notified in G.S.R. 846(E) and corrected by G.S.R. 892(E)):
  (1) Rule 7(1): Intimation to affected Data Principals (without delay)
  (2) Rule 7(2)(a): First intimation to the Data Protection Board of India (without delay)
  (3) Rule 7(2)(b): Detailed report to the Data Protection Board of India (within 72 hours of becoming aware)
"""
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum


class DataCategory(Enum):
    IDENTITY = "identity"              # name, DOB, government IDs
    CONTACT = "contact"                # email, phone, address
    FINANCIAL = "financial"            # bank accounts, card numbers, transaction history
    HEALTH = "health"                  # medical records, biometrics
    CREDENTIALS = "credentials"        # passwords, tokens, API keys
    BEHAVIORAL = "behavioral"          # browsing, location history


@dataclass
class FiduciaryContact:
    """Contact details of a person able to respond for the Data Fiduciary (Rule 7(1)(e)).
    Note: Under DPDPA Section 10(2)(a), only Significant Data Fiduciaries (SDFs) are
    required to appoint a Data Protection Officer. Non-SDFs provide contact details of
    any designated officer or privacy contact."""
    name: str
    email: str
    phone: str
    role_or_title: str = "Designated Privacy Contact"
    postal_address: str | None = None


@dataclass
class PrincipalIntimation:
    """Intimation to an affected Data Principal under Rule 7(1).

    Must be sent without delay to each affected Data Principal.
    Statutory contents:
      - Rule 7(1)(a): Description of the breach, including nature, extent, timing, and location
      - Rule 7(1)(b): Consequences of the breach, especially those relevant to this principal
      - Rule 7(1)(c): Measures taken or being taken by the Data Fiduciary to mitigate damage
      - Rule 7(1)(d): Recommended safety steps for the Data Principal
      - Rule 7(1)(e): Contact details of a person able to respond for the fiduciary
    """
    intimation_id: str
    principal_id: str
    nature: str
    extent: str                           # Rule 7(1)(a): extent of the breach
    timing: str                           # Rule 7(1)(a): timing when occurred / detected
    location: str                         # Rule 7(1)(a): location / affected systems
    consequences_for_principal: str       # Rule 7(1)(b): consequences relevant to principal
    compromised_categories: list[str]
    mitigation_measures: list[str]        # Rule 7(1)(c)
    recommended_safety_steps: list[str]   # Rule 7(1)(d)
    contact: dict                         # Rule 7(1)(e)
    language_code: str
    sent_at: str
    delivery_channel: str = "user_account"  # Rule 7(1): user account or registered contact method

    def to_dict(self) -> dict:
        return {
            "intimation_id": self.intimation_id,
            "principal_id": self.principal_id,
            "nature": self.nature,
            "extent": self.extent,
            "timing": self.timing,
            "location": self.location,
            "consequences_for_principal": self.consequences_for_principal,
            "compromised_categories": self.compromised_categories,
            "mitigation_measures": self.mitigation_measures,
            "recommended_safety_steps": self.recommended_safety_steps,
            "contact": self.contact,
            "language_code": self.language_code,
            "sent_at": self.sent_at,
            "delivery_channel": self.delivery_channel,
        }


@dataclass
class BoardFirstIntimation:
    """First intimation to the Data Protection Board of India under Rule 7(2)(a).

    Must be sent to the Board without delay upon becoming aware of a personal data breach.
    Statutory contents per Rule 7(2)(a):
      - Nature of the personal data breach
      - Extent of the personal data breach
      - Timing of the personal data breach (when occurred, when detected)
      - Location of the personal data breach
      - Likely impact of the personal data breach
      - Contact details of a person able to respond for the fiduciary
    """
    intimation_id: str
    incident_id: str
    nature: str
    extent_affected_principals: int
    timing: dict                          # occurred_at, detected_at
    location: str
    likely_impact: str
    contact: dict
    submitted_at: str
    became_aware_at: datetime | None = None
    immediate_mitigation: list[str] = field(default_factory=list)  # Optional supplementary context

    def to_dict(self) -> dict:
        return {
            "intimation_id": self.intimation_id,
            "incident_id": self.incident_id,
            "nature": self.nature,
            "extent_affected_principals": self.extent_affected_principals,
            "timing": self.timing,
            "location": self.location,
            "likely_impact": self.likely_impact,
            "immediate_mitigation": self.immediate_mitigation,
            "contact": self.contact,
            "submitted_at": self.submitted_at,
            "became_aware_at": self.became_aware_at.isoformat() if self.became_aware_at else None,
        }


@dataclass
class BoardDetailedReport:
    """Detailed report to the Data Protection Board of India under Rule 7(2)(b).

    Must be submitted to the Board within 72 hours of becoming aware of the breach,
    unless the Board extends the period upon written request.
    Statutory items per Rule 7(2)(b):
      (i) Updated and detailed information on the description given in the first intimation
      (ii) Broad facts about the events, circumstances and reasons that led to the breach
      (iii) Measures taken or proposed to mitigate risk
      (iv) Any findings about the person who caused the breach
      (v) Remedial measures taken to prevent it recurring
      (vi) A report on the intimations given to affected Data Principals
    """
    report_id: str
    incident_id: str
    first_intimation_id: str
    became_aware_at: datetime
    detailed_report_due_at: datetime
    updated_description: str                      # Item (i)
    broad_facts_and_reasons: str                  # Item (ii)
    risk_mitigation_measures: list[str]           # Item (iii)
    findings_on_person_causing_breach: str | None # Item (iv)
    remedial_measures_preventing_recurrence: list[str]  # Item (v)
    principal_intimations_report: dict            # Item (vi)
    contact: dict
    submitted_at: str
    board_extended_deadline: datetime | None = None
    affected_categories: list[str] = field(default_factory=list)
    affected_volume_records: int | None = None
    follow_up_actions: list[str] = field(default_factory=list)

    def is_overdue(self, as_of: datetime | None = None) -> bool:
        check_time = as_of or datetime.now(timezone.utc)
        effective_deadline = self.board_extended_deadline or self.detailed_report_due_at
        return check_time > effective_deadline

    def to_dict(self) -> dict:
        return {
            "report_id": self.report_id,
            "incident_id": self.incident_id,
            "first_intimation_id": self.first_intimation_id,
            "became_aware_at": self.became_aware_at.isoformat(),
            "detailed_report_due_at": self.detailed_report_due_at.isoformat(),
            "board_extended_deadline": (
                self.board_extended_deadline.isoformat() if self.board_extended_deadline else None
            ),
            "updated_description": self.updated_description,
            "broad_facts_and_reasons": self.broad_facts_and_reasons,
            "risk_mitigation_measures": self.risk_mitigation_measures,
            "findings_on_person_causing_breach": self.findings_on_person_causing_breach,
            "remedial_measures_preventing_recurrence": self.remedial_measures_preventing_recurrence,
            "principal_intimations_report": self.principal_intimations_report,
            "affected_categories": self.affected_categories,
            "affected_volume_records": self.affected_volume_records,
            "follow_up_actions": self.follow_up_actions,
            "contact": self.contact,
            "submitted_at": self.submitted_at,
        }


class BreachIntimationBuilder:
    """Builds and validates statutory breach notices under Rule 7."""

    def __init__(self, contact: FiduciaryContact):
        self.contact = contact

    def _contact_dict(self) -> dict:
        d = {
            "name": self.contact.name,
            "email": self.contact.email,
            "phone": self.contact.phone,
            "role_or_title": self.contact.role_or_title,
        }
        if self.contact.postal_address:
            d["postal_address"] = self.contact.postal_address
        return d

    def build_principal_intimation(
        self,
        principal_id: str,
        nature: str,
        extent: str,
        timing: str,
        location: str,
        consequences_for_principal: str,
        compromised_categories: list[DataCategory | str],
        mitigation_measures: list[str],
        recommended_safety_steps: list[str],
        language_code: str = "en",
        delivery_channel: str = "user_account",
    ) -> PrincipalIntimation:
        """Constructs an intimation to an affected Data Principal under Rule 7(1)."""
        if not compromised_categories:
            raise ValueError("At least one compromised data category must be declared (Rule 7(1))")
        if not recommended_safety_steps:
            raise ValueError("Recommended safety steps for the principal must be provided (Rule 7(1)(d))")
        if not extent.strip():
            raise ValueError("Extent of the breach is required (Rule 7(1)(a))")
        if not timing.strip() or not location.strip():
            raise ValueError("Timing and location of the breach are required (Rule 7(1)(a))")
        if not delivery_channel.strip():
            raise ValueError("delivery_channel is required per Rule 7(1) (e.g. user_account, email, sms)")

        cats = [c.value if isinstance(c, DataCategory) else str(c) for c in compromised_categories]

        return PrincipalIntimation(
            intimation_id=str(uuid.uuid4()),
            principal_id=principal_id,
            nature=nature,
            extent=extent,
            timing=timing,
            location=location,
            consequences_for_principal=consequences_for_principal,
            compromised_categories=cats,
            mitigation_measures=mitigation_measures,
            recommended_safety_steps=recommended_safety_steps,
            contact=self._contact_dict(),
            language_code=language_code,
            sent_at=datetime.now(timezone.utc).isoformat(),
            delivery_channel=delivery_channel,
        )

    def build_board_first_intimation(
        self,
        incident_id: str,
        nature: str,
        extent_affected_principals: int,
        location: str,
        likely_impact: str,
        immediate_mitigation: list[str] | None = None,
        detected_at: datetime | None = None,
        occurred_at: datetime | None = None,
        became_aware_at: datetime | None = None,
    ) -> BoardFirstIntimation:
        """Constructs the initial intimation to the Board under Rule 7(2)(a)."""
        if extent_affected_principals < 0:
            raise ValueError("extent_affected_principals cannot be negative")

        now = datetime.now(timezone.utc)
        timing = {
            "detected_at": (detected_at or now).isoformat(),
            "occurred_at": occurred_at.isoformat() if occurred_at else None,
        }

        return BoardFirstIntimation(
            intimation_id=str(uuid.uuid4()),
            incident_id=incident_id,
            nature=nature,
            extent_affected_principals=extent_affected_principals,
            timing=timing,
            location=location,
            likely_impact=likely_impact,
            immediate_mitigation=immediate_mitigation or [],
            contact=self._contact_dict(),
            submitted_at=now.isoformat(),
            became_aware_at=became_aware_at,
        )

    def build_board_detailed_report(
        self,
        incident_id: str,
        first_intimation_id: str,
        became_aware_at: datetime,
        updated_description: str,
        broad_facts_and_reasons: str,
        risk_mitigation_measures: list[str],
        remedial_measures_preventing_recurrence: list[str],
        principal_intimations_report: dict,
        findings_on_person_causing_breach: str | None = None,
        board_extended_deadline: datetime | None = None,
        affected_categories: list[DataCategory | str] | None = None,
        affected_volume_records: int | None = None,
        follow_up_actions: list[str] | None = None,
    ) -> BoardDetailedReport:
        """Constructs the comprehensive 72-hour report to the Board under Rule 7(2)(b)."""
        if not updated_description.strip():
            raise ValueError("Rule 7(2)(b)(i) requires updated and detailed description")
        if not broad_facts_and_reasons.strip():
            raise ValueError("Rule 7(2)(b)(ii) requires broad facts and circumstances that led to breach")
        if not risk_mitigation_measures:
            raise ValueError("Rule 7(2)(b)(iii) requires measures taken or proposed to mitigate risk")
        if not remedial_measures_preventing_recurrence:
            raise ValueError("Rule 7(2)(b)(v) requires remedial measures taken to prevent recurrence")
        if "count_sent" not in principal_intimations_report:
            raise ValueError("Rule 7(2)(b)(vi) requires report on intimations to Data Principals with count_sent")

        cats = [c.value if isinstance(c, DataCategory) else str(c) for c in (affected_categories or [])]
        now = datetime.now(timezone.utc)
        due_at = became_aware_at + timedelta(hours=72)

        return BoardDetailedReport(
            report_id=str(uuid.uuid4()),
            incident_id=incident_id,
            first_intimation_id=first_intimation_id,
            became_aware_at=became_aware_at,
            detailed_report_due_at=due_at,
            board_extended_deadline=board_extended_deadline,
            updated_description=updated_description,
            broad_facts_and_reasons=broad_facts_and_reasons,
            risk_mitigation_measures=risk_mitigation_measures,
            findings_on_person_causing_breach=findings_on_person_causing_breach,
            remedial_measures_preventing_recurrence=remedial_measures_preventing_recurrence,
            principal_intimations_report=principal_intimations_report,
            affected_categories=cats,
            affected_volume_records=affected_volume_records,
            follow_up_actions=follow_up_actions or [],
            contact=self._contact_dict(),
            submitted_at=now.isoformat(),
        )
