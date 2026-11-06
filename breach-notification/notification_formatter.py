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

    Must be sent without delay to each affected Data Principal, in a concise, clear and
    plain manner. Statutory contents, in the Rule's words:
      - Rule 7(1)(a): a description of the breach, including its nature, extent and the
        timing of its occurrence (location is NOT a 7(1)(a) element; it belongs to the
        Board notice under Rule 7(2)(a))
      - Rule 7(1)(b): the consequences relevant to her, that are likely to arise
      - Rule 7(1)(c): the measures implemented and being implemented, if any, to mitigate risk
      - Rule 7(1)(d): the safety measures she may take to protect her interests
      - Rule 7(1)(e): business contact information of a person able to respond to her queries
    `location`, `compromised_categories` and `delivery_channel` are this kit's additions,
    kept because they help a reader; they are not statutory elements.
    """
    intimation_id: str
    principal_id: str
    nature: str
    extent: str                           # Rule 7(1)(a): extent of the breach
    timing: str                           # Rule 7(1)(a): timing of its occurrence
    location: str                         # supplementary; not a Rule 7(1)(a) element; may be ""
    consequences_for_principal: str       # Rule 7(1)(b): consequences relevant to the principal
    compromised_categories: list[str]     # supplementary (kit)
    mitigation_measures: list[str]        # Rule 7(1)(c), "if any": may be empty
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
    Statutory contents per Rule 7(2)(a): "a description of the breach, including its
    nature, extent, timing and location of occurrence and the likely impact". That is:
      - nature
      - extent
      - timing of occurrence
      - location of occurrence
      - likely impact
    Supplementary, not required by 7(2)(a) but useful to the Board and to the later
    7(2)(b) report: detection time, the fiduciary's contact details, immediate mitigation,
    and the moment the fiduciary became aware (which starts the 7(2)(b) 72-hour clock).
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
            # A kit requirement so the notice names what was exposed; Rule 7(1) has no
            # data-category element.
            raise ValueError("At least one compromised data category must be declared (kit requirement, not Rule 7(1))")
        if not recommended_safety_steps:
            raise ValueError("Safety measures the principal may take are required (Rule 7(1)(d))")
        if not nature.strip() or not extent.strip() or not timing.strip():
            raise ValueError("Nature, extent and timing of occurrence are required (Rule 7(1)(a))")
        # location is not a Rule 7(1)(a) element and may be empty.
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
        # Rule 7(2)(b)(iii) reads "measures implemented or proposed, if any, to mitigate
        # risk": an empty list is a lawful answer, so it is not rejected here.
        if not remedial_measures_preventing_recurrence:
            raise ValueError("Rule 7(2)(b)(v) requires remedial measures taken to prevent recurrence")
        if "count_sent" not in principal_intimations_report:
            # Rule 7(2)(b)(vi) requires "a report regarding the intimations given to affected
            # Data Principals"; the count is how this kit makes that report checkable.
            raise ValueError(
                "principal_intimations_report needs count_sent (kit requirement inside the Rule 7(2)(b)(vi) report)"
            )

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
