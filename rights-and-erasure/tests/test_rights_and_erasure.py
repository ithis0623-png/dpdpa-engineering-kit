from datetime import datetime, timedelta, timezone

import pytest
from erasure_triggers import DataRecord, DPDPAErasureService, ErasureTrigger
from rights_service import DPDPARightsService, InMemoryInventory

NOW = datetime(2026, 10, 25, tzinfo=timezone.utc)
THREE_YEARS = timedelta(days=1095)


def record(**overrides):
    base = dict(principal_id="dp-1", purpose_key="marketplace_account", consent_status="GRANTED",
                last_approach_date=NOW - timedelta(days=30))
    base.update(overrides)
    return DataRecord(**base)


class TestErasureTriggers:
    @pytest.fixture
    def service(self):
        # Only the listed-platform purpose carries the Third Schedule period.
        return DPDPAErasureService({"marketplace_account": THREE_YEARS}, processor_registry=["ShipRocket"])

    def test_active_customer_is_not_erased(self, service):
        assert service.evaluate(record(), now=NOW).trigger is None

    @pytest.mark.parametrize(
        "overrides, trigger",
        [
            ({"consent_status": "REVOKED"}, ErasureTrigger.CONSENT_WITHDRAWAL),
            ({"pending_erasure_request": True}, ErasureTrigger.PRINCIPAL_REQUEST),
            ({"purpose_completed": True}, ErasureTrigger.PURPOSE_COMPLETION),
        ],
    )
    def test_explicit_triggers(self, service, overrides, trigger):
        evaluation = service.evaluate(record(**overrides), now=NOW)
        assert evaluation.trigger is trigger
        assert evaluation.requires_legal_hold_check
        assert evaluation.cascade_to_processors
        assert not evaluation.requires_48h_notice

    def test_inactivity_past_the_prescribed_period_needs_48h_notice(self, service):
        evaluation = service.evaluate(record(last_approach_date=NOW - timedelta(days=1100)), now=NOW)
        assert evaluation.trigger is ErasureTrigger.INACTIVITY_EXPIRY
        assert evaluation.requires_48h_notice

    def test_recent_rights_exercise_resets_inactivity(self, service):
        r = record(last_approach_date=NOW - timedelta(days=1100), last_rights_exercise_date=NOW - timedelta(days=10))
        assert service.evaluate(r, now=NOW).trigger is None

    def test_purpose_without_a_prescribed_period_never_expires_on_inactivity(self, service):
        """The SOC 2 article defaulted every purpose to three years; the Third Schedule does not."""
        r = record(purpose_key="newsletter", last_approach_date=NOW - timedelta(days=4000))
        assert service.evaluate(r, now=NOW).trigger is None

    def test_no_processors_means_no_cascade(self):
        service = DPDPAErasureService({}, processor_registry=[])
        assert not service.evaluate(record(consent_status="REVOKED"), now=NOW).cascade_to_processors


class RecordingAudit:
    def __init__(self):
        self.events = []

    def write(self, event):
        self.events.append(event)


@pytest.fixture
def rights():
    inventory = InMemoryInventory(
        systems={
            "crm": {"system_name": "CRM", "purposes": ["support"],
                    "data": {"dp-1": [{"field": "email", "value": "asha@example.in"}]}},
            "billing": {"system_name": "Billing", "purposes": ["invoicing"],
                        "data": {"dp-1": [{"field": "gstin", "value": "29ABCDE1234F1Z5"}]}},
            "analytics": {"system_name": "Analytics", "purposes": ["product"], "data": {"dp-2": []}},
        },
        sharing={"dp-1": [{"name": "ShipRocket", "role": "data_processor"}]},
        holds={"dp-1": {"billing"}},  # tax law keeps invoices
    )
    audit = RecordingAudit()
    return DPDPARightsService(inventory, audit), inventory, audit


def test_access_request_lists_data_purposes_and_recipients(rights):
    service, _, _ = rights
    resp = service.handle_access_request("dp-1")
    assert resp["status"] == "completed"
    assert {s["system"] for s in resp["data_summary"]} == {"CRM", "Billing"}
    assert resp["processors_and_fiduciaries"] == [{"name": "ShipRocket", "role": "data_processor"}]


def test_erasure_respects_legal_holds_and_says_so(rights):
    service, inventory, audit = rights
    resp = service.handle_erasure_request("dp-1", "principal_request")
    assert resp["status"] == "partially_completed"
    assert (resp["systems_erased"], resp["retention_holds"]) == (1, 1)
    assert "dp-1" not in inventory.systems["crm"]["data"]
    assert "dp-1" in inventory.systems["billing"]["data"]
    (event,) = audit.events
    assert event["systems"] == ["crm"]
    assert "asha@example.in" not in str(event)


def test_erasure_without_holds_is_completed(rights):
    service, inventory, _ = rights
    inventory.holds.clear()
    assert service.handle_erasure_request("dp-1", "consent_withdrawal")["status"] == "completed"


def test_correction_updates_held_systems_and_notifies_downstream(rights):
    """Section 12(1)-(2): Active systems are updated; held records are annotated.

    For systems under statutory preservation (e.g. tax records/invoices), historical
    records are kept intact with corrections recorded alongside as annotations.
    """
    service, inventory, audit = rights
    corrections = {
        "crm": {"email": "asha.new@example.in"},
        "billing": {"gstin": "29ABCDE9999F1Z9"},
    }

    # "billing" is held under legal retention in fixture
    assert "billing" in inventory.legal_holds("dp-1")

    resp = service.handle_correction_request("dp-1", corrections)
    assert resp["status"] == "completed"
    assert resp["fields_updated"] == 2
    assert resp["systems_overwritten"] == ["crm"]
    assert resp["systems_annotated"] == ["billing"]
    assert resp["downstream_entities_notified"] == 1

    # Verify CRM (non-held) was updated in place
    crm_data = inventory.systems["crm"]["data"]["dp-1"][0]
    assert crm_data["value"] == "asha.new@example.in"

    # Verify Billing (held) original preserved in place
    billing_data = inventory.systems["billing"]["data"]["dp-1"][0]
    assert billing_data["value"] == "29ABCDE1234F1Z5"  # original untouched

    # Verify Billing annotation recorded next to original
    assert len(inventory.annotations["billing"]["dp-1"]) == 1
    assert inventory.annotations["billing"]["dp-1"][0]["correction"] == {"gstin": "29ABCDE9999F1Z9"}

    # Downstream notification recorded without leaking raw field dicts
    assert len(service.notifier.notifications) == 1
    assert service.notifier.notifications[0]["entity"] == "ShipRocket"
    assert service.notifier.notifications[0]["signal"] == "record_updated_refetch"

    # PII kept out of audit log
    assert "asha.new@example.in" not in repr(audit.events)
    assert "29ABCDE9999F1Z9" not in repr(audit.events)


def test_correction_with_no_matching_fields_returns_rejected(rights):
    service, _, _ = rights
    corrections = {"crm": {"non_existent_field": "some_value"}}
    resp = service.handle_correction_request("dp-1", corrections)
    assert resp["status"] == "rejected"
    assert resp["fields_updated"] == 0
    assert resp["systems_overwritten"] == []
    assert resp["systems_annotated"] == []


def test_notifier_does_not_overshare_fields(rights):
    service, inventory, _ = rights
    # Configure granular shared fields
    inventory.sharing["dp-1"] = [
        {"name": "CourierCo", "role": "processor", "fields": ["shipping_address"]},
        {"name": "SupportDesk", "role": "processor", "fields": ["email"]},
    ]

    corrections = {"crm": {"email": "asha.updated@example.in"}}
    resp = service.handle_correction_request("dp-1", corrections)
    assert resp["status"] == "completed"

    # CourierCo was not given email, so CourierCo must NOT be notified
    notified_entities = [n["entity"] for n in service.notifier.notifications]
    assert "CourierCo" not in notified_entities
    assert "SupportDesk" in notified_entities

    # SupportDesk was notified ONLY for the field it holds
    support_notification = next(n for n in service.notifier.notifications if n["entity"] == "SupportDesk")
    assert support_notification["updated_fields"] == ["email"]


def test_nomination_registration_and_retrieval(rights):
    """Section 14 & Rule 14: Nomination in event of death/incapacity."""
    service, _, audit = rights
    nominee = {
        "name": "Priya Sharma",
        "relationship": "spouse",
        "contact": "priya@example.in",
    }

    resp = service.handle_nomination_request("dp-1", nominee)
    assert resp["status"] == "completed"
    assert resp["nominee_ref"].startswith("nom-")

    retrieved = service.get_nomination("dp-1")
    assert retrieved["name"] == "Priya Sharma"
    assert retrieved["relationship"] == "spouse"
    assert retrieved["nominee_ref"] == resp["nominee_ref"]

    # Audit log keeps personal data out of logs
    assert "Priya Sharma" not in repr(audit.events)
    assert "priya@example.in" not in repr(audit.events)
    nom_event = [e for e in audit.events if e.get("event") == "nomination_registered"][0]
    assert nom_event["nominee_ref"] == resp["nominee_ref"]
    assert nom_event["relationship"] == "spouse"


def test_nomination_rejected_without_name(rights):
    service, _, _ = rights
    resp = service.handle_nomination_request("dp-1", {"relationship": "child"})
    assert resp["status"] == "rejected"
    assert resp["reason"] == "invalid_nominee_details"

