# Data Principal Rights service (implements CT.DM-P1 through P4 + Sections 11, 12, 14)
#
# The two public methods are the ones from the NIST Privacy Framework article.
# The private methods the article left out are implemented against the
# DataInventory interface below; back it with your data catalogue / CMDB.
# Changed: an erasure that a legal hold partly blocked now reports
# "partially_completed" rather than "completed".
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from hashlib import sha256
from typing import Protocol


class RightType(Enum):
    ACCESS = "access"           # Section 11 - CT.DM-P1
    CORRECTION = "correction"   # Section 12 - CT.DM-P3
    ERASURE = "erasure"         # Section 12 - CT.DM-P4
    NOMINATION = "nomination"   # Section 14


class RequestStatus(Enum):
    RECEIVED = "received"
    VALIDATING = "validating"
    PROCESSING = "processing"
    COMPLETED = "completed"
    PARTIALLY_COMPLETED = "partially_completed"  # some systems kept data under a legal hold
    REJECTED = "rejected"


class DataInventory(Protocol):
    def systems_for(self, principal_id: str) -> list[dict]: ...
    def data_elements(self, system_id: str, principal_id: str) -> list[dict]: ...
    def shared_with(self, principal_id: str) -> list[dict]: ...
    def legal_holds(self, principal_id: str) -> set[str]: ...
    def erase(self, system_id: str, principal_id: str) -> dict: ...
    def update(self, system_id: str, principal_id: str, changes: dict) -> dict: ...
    def record_nomination(self, principal_id: str, nominee: dict) -> dict: ...
    def get_nomination(self, principal_id: str) -> dict | None: ...


class AuditSink(Protocol):
    def write(self, event: dict) -> None: ...


class DownstreamNotifier(Protocol):
    def notify_correction(
        self,
        principal_id: str,
        changes: dict,
        downstream_entities: list[dict],
    ) -> list[str]: ...


@dataclass
class InMemoryDownstreamNotifier:
    """Reference implementation for notifying downstream processors/fiduciaries."""
    notifications: list[dict] = field(default_factory=list)

    def notify_correction(
        self,
        principal_id: str,
        changes: dict,
        downstream_entities: list[dict],
    ) -> list[str]:
        notified = []
        for entity in downstream_entities:
            entity_name = entity.get("name", "unknown")
            self.notifications.append({
                "principal_id": principal_id,
                "entity": entity_name,
                "changes": changes,
            })
            notified.append(entity_name)
        return notified


@dataclass
class InMemoryInventory:
    """Reference inventory for tests and local runs."""

    systems: dict = field(default_factory=dict)        # system_id -> {"system_name", "purposes", "data": {pid: [...]}}
    sharing: dict = field(default_factory=dict)        # pid -> [{"name", "role"}]
    holds: dict = field(default_factory=dict)          # pid -> {system_id, ...}
    nominations: dict = field(default_factory=dict)    # pid -> nominee dict

    def systems_for(self, principal_id):
        return [{"system_id": sid, **{k: v for k, v in s.items() if k != "data"}}
                for sid, s in self.systems.items() if principal_id in s["data"]]

    def data_elements(self, system_id, principal_id):
        return list(self.systems[system_id]["data"].get(principal_id, []))

    def shared_with(self, principal_id):
        return list(self.sharing.get(principal_id, []))

    def legal_holds(self, principal_id):
        return set(self.holds.get(principal_id, set()))

    def erase(self, system_id, principal_id):
        removed = self.systems[system_id]["data"].pop(principal_id, [])
        return {"system_id": system_id, "elements_erased": len(removed)}

    def update(self, system_id, principal_id, changes):
        if system_id not in self.systems or principal_id not in self.systems[system_id]["data"]:
            return {"system_id": system_id, "fields_updated": 0}
        elements = self.systems[system_id]["data"][principal_id]
        updated = 0
        for el in elements:
            for k, v in changes.items():
                if el.get("field") == k:
                    el["value"] = v
                    updated += 1
                elif k in el:
                    el[k] = v
                    updated += 1
        return {"system_id": system_id, "fields_updated": updated}

    def record_nomination(self, principal_id, nominee):
        self.nominations[principal_id] = nominee
        return nominee

    def get_nomination(self, principal_id):
        return self.nominations.get(principal_id)


class DPDPARightsService:
    """
    Implements DPDPA Data Principal rights mapped to NIST Control-P subcategories.
    Each method traces to both the NIST subcategory and the DPDPA section it satisfies.
    """

    def __init__(
        self,
        inventory: DataInventory,
        audit: AuditSink,
        notifier: DownstreamNotifier | None = None,
    ):
        self.inventory = inventory
        self.audit = audit
        self.notifier = notifier or InMemoryDownstreamNotifier()

    def handle_access_request(
        self, principal_id: str
    ) -> dict:
        """
        NIST: CT.DM-P1 (data accessible for review)
        DPDPA: Section 11 -- summary of personal data and processing activities

        Returns: summary including all data elements, purposes, and downstream
        processors/fiduciaries (required by Section 11(1)(b)).
        """
        request_id = str(uuid.uuid4())
        # Query data processing inventory (built under ID.IM-P8)
        data_summary = self._compile_data_summary(principal_id)
        processor_list = self._get_downstream_entities(principal_id)

        return {
            "request_id": request_id,
            "right_type": RightType.ACCESS.value,
            "status": RequestStatus.COMPLETED.value,
            "data_summary": data_summary,
            "processors_and_fiduciaries": processor_list,  # S.11(1)(b)
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

    def handle_erasure_request(
        self, principal_id: str, reason: str
    ) -> dict:
        """
        NIST: CT.DM-P4 (data accessible for deletion) + CT.DM-P5 (destroyed per policy)
        DPDPA: Section 8(7) -- erasure on consent withdrawal or purpose completion
               Section 12 -- right to erasure on request

        Triggers cascading delete across all systems in the data inventory.
        Preserves audit record of the erasure event (CT.DM-P8 + Rule 6(1)(c)).
        """
        request_id = str(uuid.uuid4())
        # Identify all systems holding this principal's data (ID.IM-P1)
        affected_systems = self._get_systems_for_principal(principal_id)

        # Check legal retention holds before erasure (Section 8(7) retention obligation)
        retention_holds = self._check_retention_holds(principal_id)

        erasure_results = []
        for system in affected_systems:
            if system["system_id"] not in retention_holds:
                result = self._execute_erasure(system, principal_id)
                erasure_results.append(result)

        # Log the erasure event -- retained for 1 year per Rule 6(1)(e)
        self._log_erasure_audit(request_id, principal_id, erasure_results, reason)

        held = [s for s in affected_systems if s["system_id"] in retention_holds]
        status = RequestStatus.PARTIALLY_COMPLETED if held else RequestStatus.COMPLETED
        return {
            "request_id": request_id,
            "right_type": RightType.ERASURE.value,
            "status": status.value,
            "systems_erased": len(erasure_results),
            "retention_holds": len(held),
            "completed_at": datetime.now(timezone.utc).isoformat(),
        }

    def handle_correction_request(
        self,
        principal_id: str,
        corrections: dict[str, dict],
        reason: str = "correction",
    ) -> dict:
        """
        NIST: CT.DM-P3 (data accessible for correction)
        DPDPA: Section 12(1)-(2) -- correction, completion, and updating of personal data

        Statutory Scope:
          - Section 8(7) legal retention holds prevent *erasure*, not correction. A retention
            obligation is no justification for maintaining inaccurate or misleading records.
            Therefore, held systems are updated rather than skipped.
          - Section 12(1) requires the Data Fiduciary to notify all downstream entities
            (processors and other fiduciaries) of the corrected data.
        """
        request_id = str(uuid.uuid4())
        affected_systems = self._get_systems_for_principal(principal_id)

        update_results = []
        for system in affected_systems:
            sid = system["system_id"]
            if sid in corrections:
                result = self.inventory.update(sid, principal_id, corrections[sid])
                update_results.append(result)

        # Notify downstream entities per Section 12(1)
        downstream = self._get_downstream_entities(principal_id)
        notified_entities = self.notifier.notify_correction(principal_id, corrections, downstream)

        self._log_correction_audit(request_id, principal_id, update_results, reason)

        return {
            "request_id": request_id,
            "right_type": RightType.CORRECTION.value,
            "status": RequestStatus.COMPLETED.value,
            "systems_updated": len(update_results),
            "downstream_entities_notified": len(notified_entities),
            "completed_at": datetime.now(timezone.utc).isoformat(),
        }

    def handle_nomination_request(
        self,
        principal_id: str,
        nominee: dict,
    ) -> dict:
        """
        DPDPA: Section 14 -- Right of nomination in the event of death or incapacity
        DPDP Rules, 2025: Rule 14 -- Readily available means of exercising rights

        Note: Personal data of the nominee is never written into the audit log;
        only a pseudonymous reference token is recorded.
        """
        request_id = str(uuid.uuid4())
        if not isinstance(nominee, dict) or not nominee.get("name"):
            return {
                "request_id": request_id,
                "right_type": RightType.NOMINATION.value,
                "status": RequestStatus.REJECTED.value,
                "reason": "invalid_nominee_details",
            }

        recorded = self.inventory.record_nomination(principal_id, nominee)
        nominee_ref = f"nom-{sha256(nominee['name'].encode('utf-8')).hexdigest()[:12]}"

        self.audit.write({
            "event": "nomination_registered",
            "request_id": request_id,
            "principal_id": principal_id,
            "nominee_ref": nominee_ref,
            "relationship": nominee.get("relationship"),
            "at": datetime.now(timezone.utc).isoformat(),
        })

        return {
            "request_id": request_id,
            "right_type": RightType.NOMINATION.value,
            "status": RequestStatus.COMPLETED.value,
            "nominee_ref": nominee_ref,
            "nominee": recorded,
            "registered_at": datetime.now(timezone.utc).isoformat(),
        }

    def get_nomination(self, principal_id: str) -> dict | None:
        """Retrieves active nomination record under Section 14."""
        return self.inventory.get_nomination(principal_id)

    def _log_correction_audit(self, req_id: str, pid: str, results: list, reason: str) -> None:
        # Audit record names systems and count, never the personal data values
        self.audit.write({
            "event": "correction_executed",
            "request_id": req_id,
            "principal_id": pid,
            "reason": reason,
            "systems": [r["system_id"] for r in results],
            "at": datetime.now(timezone.utc).isoformat(),
        })

    def _compile_data_summary(self, principal_id: str) -> list[dict]:
        return [
            {
                "system": s["system_name"],
                "purposes": s.get("purposes", []),
                "data_elements": self.inventory.data_elements(s["system_id"], principal_id),
            }
            for s in self.inventory.systems_for(principal_id)
        ]

    def _get_downstream_entities(self, principal_id: str) -> list[dict]:
        return self.inventory.shared_with(principal_id)

    def _get_systems_for_principal(self, principal_id: str) -> list[dict]:
        return self.inventory.systems_for(principal_id)

    def _check_retention_holds(self, principal_id: str) -> set[str]:
        return self.inventory.legal_holds(principal_id)

    def _execute_erasure(self, system: dict, principal_id: str) -> dict:
        return self.inventory.erase(system["system_id"], principal_id)

    def _log_erasure_audit(self, req_id: str, pid: str, results: list, reason: str) -> None:
        # The audit record names systems and counts, never the erased values.
        self.audit.write({
            "event": "erasure_executed",
            "request_id": req_id,
            "principal_id": pid,
            "reason": reason,
            "systems": [r["system_id"] for r in results],
            "at": datetime.now(timezone.utc).isoformat(),
        })
