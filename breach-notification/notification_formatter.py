"""
notification_formatter.py

Implements statutory personal data breach intimations under DPDPA Section 8(6)
and DPDP Rules, 2025 Rule 7:
  (1) Rule 7(1): Intimation to affected Data Principals (without delay)
  (2) Rule 7(2)(a): First intimation to the Data Protection Board of India (without delay)
  (3) Rule 7(2)(b): Detailed report to the Data Protection Board of India (within 72 hours)
"""
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
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
      - Rule 7(1)(a): Description of the breach, including nature, timing, and location
      - Rule 7(1)(b): Consequences of the breach, especially those relevant to this principal
      - Rule 7(1)(c): Measures taken or being taken by the Data Fiduciary to mitigate damage
      - Rule 7(1)(d): Recommended safety steps for the Data Principal
      - Rule 7(1)(e): Contact details of a person able to respond for the fiduciary
    """
    intimation_id: str
    principal_id: str
    nature: str
    timing: str                           # when the breach occurred / was detected
    location: str                         # affected service, component, or system
    consequences_for_principal: str       # specific likely consequences for this principal
    compromised_categories: list[str]
    mitigation_measures: list[str]
    recommended_safety_steps: list[str]
    contact: dict
    language_code: str
    sent_at: str

    def to_dict(self) -> dict:
        return {
            "intimation_id": self.intimation_id,
            "principal_id": self.principal_id,
            "nature": self.nature,
            "timing": self.timing,
            "location": self.location,
            "consequences_for_principal": self.consequences_for_principal,
            "compromised_categories": self.compromised_categories,
            "mitigation_measures": self.mitigation_measures,
            "recommended_safety_steps": self.recommended_safety_steps,
            "contact": self.contact,
            "language_code": self.language_code,
            "sent_at": self.sent_at,
        }


@dataclass
class BoardFirstIntimation:
    """First intimation to the Data Protection Board of India under Rule 7(2)(a).

    Must be sent to the Board without delay upon becoming aware of a personal data breach.
    Statutory contents:
      - Nature of the personal data breach
      - Extent of the personal data breach (estimated number of affected principals/records)
      - Timing of the breach (when occurred, when detected)
      - Location of the breach (systems, services, regions)
      - Likely impact / risks
      - Immediate mitigation measures taken
      - Contact details of a person able to respond
    """
    intimation_id: str
    incident_id: str
    nature: str
    extent_affected_principals: int
    timing: dict                          # occurred_at, detected_at
    location: str
    likely_impact: str
    immediate_mitigation: list[str]
    contact: dict
    submitted_at: str

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
        }


@dataclass
class BoardDetailedReport:
    """Detailed report to the Data Protection Board of India under Rule 7(2)(b).

    Must be submitted to the Board within 72 hours of becoming aware of the breach.
    Covers items (i) to (vi):
      (i) Detailed description, root cause and timeline
      (ii) Categories and volume of personal data affected
      (iii) Extent and consequences on Data Principals and operations
      (iv) Remedial actions and mitigation measures taken and proposed
      (v) Report on intimations sent to affected Data Principals under Rule 7(1)
      (vi) Follow-up actions and ongoing monitoring
    """
    report_id: str
    incident_id: str
    first_intimation_id: str
    root_cause_and_timeline: str
    affected_categories: list[str]
    affected_volume_records: int
    consequences_assessment: str
    remedial_measures_taken: list[str]
    remedial_measures_planned: list[str]
    principal_intimations_report: dict    # count_sent, channels_used, date_commenced, summary
    follow_up_actions: list[str]
    contact: dict
    submitted_at: str

    def to_dict(self) -> dict:
        return {
            "report_id": self.report_id,
            "incident_id": self.incident_id,
            "first_intimation_id": self.first_intimation_id,
            "root_cause_and_timeline": self.root_cause_and_timeline,
            "affected_categories": self.affected_categories,
            "affected_volume_records": self.affected_volume_records,
            "consequences_assessment": self.consequences_assessment,
            "remedial_measures_taken": self.remedial_measures_taken,
            "remedial_measures_planned": self.remedial_measures_planned,
            "principal_intimations_report": self.principal_intimations_report,
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
        timing: str,
        location: str,
        consequences_for_principal: str,
        compromised_categories: list[DataCategory | str],
        mitigation_measures: list[str],
        recommended_safety_steps: list[str],
        language_code: str = "en",
    ) -> PrincipalIntimation:
        """Constructs an intimation to an affected Data Principal under Rule 7(1)."""
        if not compromised_categories:
            raise ValueError("At least one compromised data category must be declared (Rule 7(1))")
        if not recommended_safety_steps:
            raise ValueError("Recommended safety steps for the principal must be provided (Rule 7(1)(d))")
        if not timing.strip() or not location.strip():
            raise ValueError("Timing and location of the breach are required (Rule 7(1)(a))")

        cats = [c.value if isinstance(c, DataCategory) else str(c) for c in compromised_categories]

        return PrincipalIntimation(
            intimation_id=str(uuid.uuid4()),
            principal_id=principal_id,
            nature=nature,
            timing=timing,
            location=location,
            consequences_for_principal=consequences_for_principal,
            compromised_categories=cats,
            mitigation_measures=mitigation_measures,
            recommended_safety_steps=recommended_safety_steps,
            contact=self._contact_dict(),
            language_code=language_code,
            sent_at=datetime.now(timezone.utc).isoformat(),
        )

    def build_board_first_intimation(
        self,
        incident_id: str,
        nature: str,
        extent_affected_principals: int,
        location: str,
        likely_impact: str,
        immediate_mitigation: list[str],
        detected_at: datetime | None = None,
        occurred_at: datetime | None = None,
    ) -> BoardFirstIntimation:
        """Constructs the initial intimation to the Board under Rule 7(2)(a)."""
        if extent_affected_principals < 0:
            raise ValueError("extent_affected_principals cannot be negative")
        if not immediate_mitigation:
            raise ValueError("Immediate mitigation measures must be documented (Rule 7(2)(a))")

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
            immediate_mitigation=immediate_mitigation,
            contact=self._contact_dict(),
            submitted_at=now.isoformat(),
        )

    def build_board_detailed_report(
        self,
        incident_id: str,
        first_intimation_id: str,
        root_cause_and_timeline: str,
        affected_categories: list[DataCategory | str],
        affected_volume_records: int,
        consequences_assessment: str,
        remedial_measures_taken: list[str],
        remedial_measures_planned: list[str],
        principal_intimations_report: dict,
        follow_up_actions: list[str] | None = None,
    ) -> BoardDetailedReport:
        """Constructs the comprehensive 72-hour report to the Board under Rule 7(2)(b)."""
        if affected_volume_records < 0:
            raise ValueError("affected_volume_records cannot be negative")
        if not affected_categories:
            raise ValueError("Affected categories must be documented (Rule 7(2)(b)(ii))")
        if not remedial_measures_taken:
            raise ValueError("Remedial measures taken must be documented (Rule 7(2)(b)(iv))")
        if "count_sent" not in principal_intimations_report:
            raise ValueError("principal_intimations_report must include count_sent (Rule 7(2)(b)(v))")

        cats = [c.value if isinstance(c, DataCategory) else str(c) for c in affected_categories]
        now = datetime.now(timezone.utc)

        return BoardDetailedReport(
            report_id=str(uuid.uuid4()),
            incident_id=incident_id,
            first_intimation_id=first_intimation_id,
            root_cause_and_timeline=root_cause_and_timeline,
            affected_categories=cats,
            affected_volume_records=affected_volume_records,
            consequences_assessment=consequences_assessment,
            remedial_measures_taken=remedial_measures_taken,
            remedial_measures_planned=remedial_measures_planned,
            principal_intimations_report=principal_intimations_report,
            follow_up_actions=follow_up_actions or [],
            contact=self._contact_dict(),
            submitted_at=now.isoformat(),
        )
