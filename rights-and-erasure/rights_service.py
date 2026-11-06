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
    def annotate(self, system_id: str, principal_id: str, changes: dict) -> dict: ...
    def record_nomination(self, principal_id: str, nominee: dict) -> dict: ...
    def get_nomination(self, principal_id: str) -> dict | None: ...


class AuditSink(Protocol):
    def write(self, event: dict) -> None: ...


class DownstreamNotifier(Protocol):
    def notify_correction(
        self,
        principal_id: str,
        downstream_entities: list[dict],
        updated_fields_by_system: dict[str, list[str]],
    ) -> list[str]: ...


@dataclass
class InMemoryDownstreamNotifier:
    """Reference implementation for notifying downstream processors/fiduciaries.
    Prevents over-sharing by notifying entities only of fields they received, or sending
    a 'record_updated_refetch' signal without disclosing raw values from other systems."""
    notifications: list[dict] = field(default_factory=list)

    def notify_correction(
        self,
        principal_id: str,
        downstream_entities: list[dict],
        updated_fields_by_system: dict[str, list[str]],
    ) -> list[str]:
        all_updated_fields = set()
        for fields in updated_fields_by_system.values():
            all_updated_fields.update(fields)

        notified = []
        for entity in downstream_entities:
            entity_name = entity.get("name", "unknown")
            entity_fields = entity.get("fields")
            if entity_fields is not None:
                relevant = [f for f in all_updated_fields if f in entity_fields]
                if not relevant:
                    continue  # Entity did not receive any of the updated fields
                payload = {
                    "principal_id": principal_id,
                    "entity": entity_name,
                    "updated_fields": relevant,
                }
            else:
                payload = {
                    "principal_id": principal_id,
                    "entity": entity_name,
                    "signal": "record_updated_refetch",
                }
            self.notifications.append(payload)
            notified.append(entity_name)
        return notified


@dataclass
class InMemoryInventory:
    """Reference inventory for tests and local runs."""

    systems: dict = field(default_factory=dict)        # system_id -> {"system_name", "purposes", "data": {pid: [...]}}
    sharing: dict = field(default_factory=dict)        # pid -> [{"name", "role", "fields": [...]}]
    holds: dict = field(default_factory=dict)          # pid -> {system_id, ...}
    nominations: dict = field(default_factory=dict)    # pid -> nominee dict
    annotations: dict = field(default_factory=dict)    # system_id -> {pid: [{"correction", "annotated_at"}]}

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
            return {"system_id": system_id, "fields_updated": 0, "updated_field_names": []}
        elements = self.systems[system_id]["data"][principal_id]
        updated = 0
        updated_names = []
        for el in elements:
            for k, v in changes.items():
                if el.get("field") == k:
                    el["value"] = v
                    updated += 1
                    updated_names.append(k)
                elif k in el:
                    el[k] = v
                    updated += 1
                    updated_names.append(k)
        return {"system_id": system_id, "fields_updated": updated, "updated_field_names": updated_names}

    def annotate(self, system_id, principal_id, changes):
        """Records correction as an annotation next to original for held legal records (e.g. tax invoices)."""
        if system_id not in self.systems or principal_id not in self.systems[system_id]["data"]:
            return {"system_id": system_id, "fields_annotated": 0, "updated_field_names": []}
        if system_id not in self.annotations:
            self.annotations[system_id] = {}
        if principal_id not in self.annotations[system_id]:
            self.annotations[system_id][principal_id] = []
        self.annotations[system_id][principal_id].append({
            "correction": changes,
            "annotated_at": datetime.now(timezone.utc).isoformat(),
        })
        elements = self.systems[system_id]["data"][principal_id]
        existing_fields = {el.get("field") for el in elements}
        matched = [k for k in changes if k in existing_fields or any(k in el for el in elements)]
        return {"system_id": system_id, "fields_annotated": len(matched), "updated_field_names": matched}

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
          - Section 12 obliges the Data Fiduciary itself to correct, complete, and update data.
            Notifying downstream entities is good engineering practice aligned with Section 8(3)'s
            accuracy obligation upon disclosure to another fiduciary/processor.
          - Legal holds (e.g. tax invoice preservation): Overwriting original tax documents
            can violate other statutory retention duties. For held systems, corrections are
            recorded as annotations/versions next to the original, while non-held systems
            are updated in place.
          - Reports fields_updated and returns REJECTED status if no fields matched.
        """
        request_id = str(uuid.uuid4())
        affected_systems = self._get_systems_for_principal(principal_id)
        retention_holds = self._check_retention_holds(principal_id)

        systems_overwritten = []
        systems_annotated = []
        updated_fields_by_system: dict[str, list[str]] = {}
        total_fields_updated = 0

        for system in affected_systems:
            sid = system["system_id"]
            if sid in corrections:
                changes = corrections[sid]
                if sid in retention_holds:
                    # Record correction next to original without overwriting preserved historical record
                    res = self.inventory.annotate(sid, principal_id, changes)
                    count = res.get("fields_annotated", 0)
                    if count > 0:
                        systems_annotated.append(sid)
                        total_fields_updated += count
                        updated_fields_by_system[sid] = res.get("updated_field_names", list(changes.keys()))
                else:
                    # Standard active record: update in place
                    res = self.inventory.update(sid, principal_id, changes)
                    count = res.get("fields_updated", 0)
                    if count > 0:
                        systems_overwritten.append(sid)
                        total_fields_updated += count
                        updated_fields_by_system[sid] = res.get("updated_field_names", list(changes.keys()))

        # Downstream notification (good practice / Section 8(3) accuracy support)
        downstream = self._get_downstream_entities(principal_id)
        notified_entities = self.notifier.notify_correction(
            principal_id=principal_id,
            downstream_entities=downstream,
            updated_fields_by_system=updated_fields_by_system,
        )

        all_touched_systems = systems_overwritten + systems_annotated
        self._log_correction_audit(request_id, principal_id, all_touched_systems, reason)

        status = RequestStatus.COMPLETED if total_fields_updated > 0 else RequestStatus.REJECTED

        return {
            "request_id": request_id,
            "right_type": RightType.CORRECTION.value,
            "status": status.value,
            "fields_updated": total_fields_updated,
            "systems_overwritten": systems_overwritten,
            "systems_annotated": systems_annotated,
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

        Note: Personal data of the nominee is never written into the audit log.
        A random UUID nomination reference token is generated, stored next to the record,
        and logged in the audit trail, preventing rainbow table / dictionary reversals.
        """
        request_id = str(uuid.uuid4())
        if not isinstance(nominee, dict) or not nominee.get("name"):
            return {
                "request_id": request_id,
                "right_type": RightType.NOMINATION.value,
                "status": RequestStatus.REJECTED.value,
                "reason": "invalid_nominee_details",
            }

        # Generate a random, unguessable nomination ID stored next to the record
        nominee_ref = f"nom-{uuid.uuid4().hex[:16]}"
        record_payload = dict(nominee)
        record_payload["nominee_ref"] = nominee_ref

        recorded = self.inventory.record_nomination(principal_id, record_payload)

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

    def _log_correction_audit(self, req_id: str, pid: str, systems: list[str], reason: str) -> None:
        # Audit record names systems and counts, never personal data values
        self.audit.write({
            "event": "correction_executed",
            "request_id": req_id,
            "principal_id": pid,
            "reason": reason,
            "systems": systems,
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
