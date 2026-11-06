import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from breach_classifier import ClassificationResult, classify
from notification_formatter import (
    BreachIntimationBuilder,
    DataCategory,
    FiduciaryContact,
)

HERE = Path(__file__).resolve().parent.parent


@pytest.mark.parametrize(
    "incident, expected",
    [
        ({"contains_personal_data": False, "action": "exfiltration"}, ClassificationResult.NOT_A_BREACH),
        ({"contains_personal_data": True, "is_authorised": True, "action": "data_deletion"},
         ClassificationResult.NOT_A_BREACH),
        ({"contains_personal_data": True, "action": "exfiltration"}, ClassificationResult.CONFIRMED_BREACH),
        ({"contains_personal_data": True, "action": "Ransomware"}, ClassificationResult.CONFIRMED_BREACH),
        ({"contains_personal_data": True, "action": "port_scan"}, ClassificationResult.ESCALATE_TO_DPO),
        ({"contains_personal_data": True}, ClassificationResult.ESCALATE_TO_DPO),
    ],
)
def test_section_2u_gates(incident, expected):
    assert classify(incident) is expected


@pytest.mark.parametrize("siem_action", ["DataExfiltration", "UnauthorizedAccess", "DataModification", "DataDeletion"])
def test_every_siem_action_is_classified_without_escalation(siem_action):
    """The SIEM rule and the classifier must agree on action names."""
    assert classify({"contains_personal_data": True, "action": siem_action}) is ClassificationResult.CONFIRMED_BREACH


def _conf_stanzas(text: str) -> dict:
    """Parse a Splunk .conf file the way Splunk does: whole-line comments, backslash continuations."""
    stanzas, current, key, buf = {}, None, None, []
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.rstrip()
        if key is not None:  # inside a continued value
            assert not line.lstrip().startswith("#"), f"line {lineno}: comment inside a multi-line value"
            buf.append(line[:-1] if line.endswith("\\") else line)
            if not line.endswith("\\"):
                stanzas[current][key] = "\n".join(buf)
                key = None
            continue
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if m := re.fullmatch(r"\[(.+)\]", line.strip()):
            current = m.group(1)
            stanzas[current] = {}
            continue
        k, sep, v = line.partition("=")
        assert sep, f"line {lineno}: expected key = value"
        k, v = k.strip(), v.strip()
        if v.endswith("\\"):
            key, buf = k, [v[:-1]]
        else:
            stanzas[current][k] = v
    assert key is None, "file ends inside a continued value"
    return stanzas


def test_savedsearch_is_valid_conf_and_matches_the_classifier():
    stanza = _conf_stanzas((HERE / "savedsearches.conf").read_text(encoding="utf-8"))["dpdpa_breach_detection"]
    search = stanza["search"]
    assert search.startswith("index=security")
    assert "#" not in search, "SPL has no # comments; use ``` ... ```"
    assert search.count("```") % 2 == 0
    assert search.count("(") == search.count(")")
    assert stanza["action.webhook"] == "1"
    assert stanza["action.webhook.param.url"].startswith("https://")

    for action in re.findall(r"action=(\w+)", search):
        if action != "AccessDenied_Anomalous":  # availability signal; deliberately left for DPO triage
            result = classify({"contains_personal_data": True, "action": action})
            assert result is ClassificationResult.CONFIRMED_BREACH, action


@pytest.fixture
def contact():
    return FiduciaryContact(
        name="Ananya Roy",
        email="privacy-contact@example.in",
        phone="+91-11-23456789",
        role_or_title="Designated Grievance & Privacy Officer",
    )


def test_principal_intimation_rule_7_1(contact):
    builder = BreachIntimationBuilder(contact)
    notice = builder.build_principal_intimation(
        principal_id="dp-9988",
        nature="Unauthorised access to user database replica",
        extent="Single database table replica containing 1200 user records",
        timing="2026-11-01 14:30 UTC",
        location="ap-south-1 replica database",
        consequences_for_principal="Your contact number may receive targeted phishing SMS or calls.",
        compromised_categories=[DataCategory.CONTACT],
        mitigation_measures=["The compromised read-replica was quarantined within 20 minutes."],
        recommended_safety_steps=["Be alert to suspicious phone calls or SMS messages asking for OTPs."],
        language_code="en",
    )

    d = notice.to_dict()
    assert d["principal_id"] == "dp-9988"
    assert d["extent"] == "Single database table replica containing 1200 user records"
    assert d["timing"] == "2026-11-01 14:30 UTC"
    assert d["location"] == "ap-south-1 replica database"
    assert "phishing" in d["consequences_for_principal"]
    assert d["compromised_categories"] == ["contact"]
    assert d["contact"]["name"] == "Ananya Roy"


def test_principal_intimation_validation_errors(contact):
    builder = BreachIntimationBuilder(contact)
    with pytest.raises(ValueError, match="Timing and location"):
        builder.build_principal_intimation(
            principal_id="dp-1",
            nature="leak",
            extent="one cluster",
            timing="",
            location="",
            consequences_for_principal="test",
            compromised_categories=[DataCategory.CONTACT],
            mitigation_measures=["patched"],
            recommended_safety_steps=["change password"],
        )

    with pytest.raises(ValueError, match="Extent of the breach is required"):
        builder.build_principal_intimation(
            principal_id="dp-1",
            nature="leak",
            extent="   ",
            timing="2026-11-01",
            location="server-1",
            consequences_for_principal="test",
            compromised_categories=[DataCategory.CONTACT],
            mitigation_measures=["patched"],
            recommended_safety_steps=["change password"],
        )


def test_board_first_intimation_rule_7_2_a_without_mandatory_mitigation(contact):
    """First notice must not be blocked when immediate mitigation is not yet available."""
    builder = BreachIntimationBuilder(contact)
    first_notice = builder.build_board_first_intimation(
        incident_id="INC-2026-101",
        nature="Unauthorised database exfiltration via compromised API token",
        extent_affected_principals=1200,
        location="Core Accounts Cluster, ap-south-1",
        likely_impact="Risk of identity theft and credential reuse for 1200 principals",
    )

    data = first_notice.to_dict()
    assert data["incident_id"] == "INC-2026-101"
    assert data["extent_affected_principals"] == 1200
    assert "detected_at" in data["timing"]
    assert data["immediate_mitigation"] == []


def test_board_detailed_report_rule_7_2_b_and_72h_clock(contact):
    builder = BreachIntimationBuilder(contact)
    aware_time = datetime(2026, 11, 1, 10, 0, tzinfo=timezone.utc)

    report = builder.build_board_detailed_report(
        incident_id="INC-2026-101",
        first_intimation_id="INT-FIRST-001",
        became_aware_at=aware_time,
        updated_description="Detailed assessment confirms 1200 identity & financial records exfiltrated.",
        broad_facts_and_reasons=(
            "Root cause was an exposed staging credential. Access began at 10:00, detected at 10:45."
        ),
        risk_mitigation_measures=["Staging environment isolated", "All secrets rotated in AWS Secrets Manager"],
        findings_on_person_causing_breach="External unauthorized attacker using Tor exit node IPs",
        remedial_measures_preventing_recurrence=["Mandatory hardware MFA rollout across all engineering accounts"],
        principal_intimations_report={
            "count_sent": 1200,
            "channels_used": ["email", "sms"],
            "date_commenced": "2026-11-02T12:00:00Z",
            "summary": "1,192 delivered, 8 bounced",
        },
        affected_categories=[DataCategory.IDENTITY, DataCategory.FINANCIAL],
        affected_volume_records=2500,
        follow_up_actions=["Scheduled external penetration testing with CERT-In empaneled auditor"],
    )

    d = report.to_dict()
    assert d["report_id"]
    assert d["became_aware_at"] == aware_time.isoformat()
    assert d["detailed_report_due_at"] == (aware_time + timedelta(hours=72)).isoformat()
    assert d["findings_on_person_causing_breach"] == "External unauthorized attacker using Tor exit node IPs"
    assert d["affected_volume_records"] == 2500
    assert d["principal_intimations_report"]["count_sent"] == 1200
    assert len(d["risk_mitigation_measures"]) == 2

    # Check 72-hour clock
    assert report.is_overdue(as_of=aware_time + timedelta(hours=71)) is False
    assert report.is_overdue(as_of=aware_time + timedelta(hours=73)) is True

    # Board extension
    report.board_extended_deadline = aware_time + timedelta(hours=120)
    assert report.is_overdue(as_of=aware_time + timedelta(hours=73)) is False
    assert report.is_overdue(as_of=aware_time + timedelta(hours=121)) is True

