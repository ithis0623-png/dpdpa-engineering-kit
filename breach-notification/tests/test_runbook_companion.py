import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from breach_deadlines import breach_deadlines, overdue
from incident_log import IncidentLog
from pydantic import ValidationError

HERE = Path(__file__).resolve().parent.parent
TEMPLATES = HERE / "templates"
IST = timezone(timedelta(hours=5, minutes=30))
T = datetime(2027, 6, 3, 14, 10, tzinfo=IST)
N = datetime(2027, 6, 3, 13, 5, tzinfo=IST)


def _by_key(deadlines):
    return {d.key: d for d in deadlines}


def test_detailed_board_report_is_72_hours_from_aware():
    d = _by_key(breach_deadlines(T))
    assert d["board_detailed"].due == T + timedelta(hours=72)
    assert d["board_detailed"].in_law


def test_first_intimations_have_no_fixed_hour():
    """Rule 7(1) and 7(2)(a) say "without delay": no due time, so no one waits for one."""
    d = _by_key(breach_deadlines(T))
    assert d["data_principals"].due is None
    assert d["board_first"].due is None


def test_cert_in_runs_from_noticed_not_aware():
    d = _by_key(breach_deadlines(T, noticed_at=N, cert_in_applies=True))
    assert d["cert_in"].due == N + timedelta(hours=6)
    assert d["cert_in"].due < T + timedelta(hours=6)


def test_no_cert_in_deadline_unless_it_applies():
    assert "cert_in" not in _by_key(breach_deadlines(T, noticed_at=N))


def test_cert_in_needs_the_noticed_time():
    with pytest.raises(ValueError, match="noticed_at"):
        breach_deadlines(T, cert_in_applies=True)


def test_longer_period_check_is_a_runbook_target_at_hour_48():
    d = _by_key(breach_deadlines(T))
    assert d["longer_period_check"].due == T + timedelta(hours=48)
    assert not d["longer_period_check"].in_law


def test_a_longer_period_the_board_allowed_replaces_72_hours():
    allowed = T + timedelta(days=7)
    d = _by_key(breach_deadlines(T, board_allowed_until=allowed))
    assert d["board_detailed"].due == allowed
    assert "longer_period_check" not in d


def test_a_longer_period_must_be_longer():
    with pytest.raises(ValueError, match="later than"):
        breach_deadlines(T, board_allowed_until=T + timedelta(hours=24))


def test_times_without_a_timezone_are_refused():
    with pytest.raises(ValueError, match="timezone"):
        breach_deadlines(datetime(2027, 6, 3, 14, 10))


def test_overdue_lists_only_passed_fixed_deadlines():
    deadlines = breach_deadlines(T, noticed_at=N, cert_in_applies=True)
    late = overdue(deadlines, N + timedelta(hours=7))
    assert [d.key for d in late] == ["cert_in"]
    assert {d.key for d in overdue(deadlines, T + timedelta(hours=73))} == {"cert_in", "longer_period_check",
                                                                              "board_detailed"}


def _example() -> IncidentLog:
    return IncidentLog.model_validate(json.loads((TEMPLATES / "e-incident-log.example.json").read_text("utf-8")))


def test_example_log_validates_and_meets_its_own_deadlines():
    log = _example()
    d = _by_key(breach_deadlines(log.aware_at, noticed_at=log.noticed_at, cert_in_applies=True))
    cert_in_sent = next(e.at for e in log.entries if e.message and e.message.to.value == "cert_in")
    assert cert_in_sent <= d["cert_in"].due
    assert {dec.number for dec in log.decisions} <= set(range(1, 7))


def test_intimation_report_feeds_rule_7_2_b_vi():
    report = _example().intimation_report()
    assert report["messages_sent"] == 1840 + 23
    assert report["failed"] == 23
    assert report["by_channel"]["registered email"] == {"sent": 1840, "failed": 23}
    assert report["first_sent_at"].startswith("2027-06-03T19:00")


def test_log_entries_must_be_in_time_order():
    data = json.loads((TEMPLATES / "e-incident-log.example.json").read_text("utf-8"))
    data["entries"].reverse()
    with pytest.raises(ValidationError, match="time order"):
        IncidentLog.model_validate(data)


def test_log_times_need_a_timezone():
    data = json.loads((TEMPLATES / "e-incident-log.example.json").read_text("utf-8"))
    data["aware_at"] = "2027-06-03T14:10:00"
    with pytest.raises(ValidationError):
        IncidentLog.model_validate(data)


def test_template_a_answers_all_five_rule_7_1_items():
    text = (TEMPLATES / "a-data-principal-intimation.md").read_text("utf-8")
    for item in "abcde":
        assert f"[7(1)({item})]" in text


def test_template_b_asks_for_the_five_rule_7_2_a_items():
    text = (TEMPLATES / "b-board-first-intimation.md").read_text("utf-8")
    rows = [line for line in text.splitlines() if line.startswith("|") and "[7(2)(a)]" in line]
    named = " ".join(rows).lower()
    assert len(rows) == 5
    for item in ("nature", "extent", "timing", "location", "likely impact"):
        assert item in named


def test_template_c_has_the_six_rule_7_2_b_headings():
    text = (TEMPLATES / "c-board-detailed-report.md").read_text("utf-8")
    assert re.findall(r"^\| \((i|ii|iii|iv|v|vi)\) ", text, re.M) == ["i", "ii", "iii", "iv", "v", "vi"]


@pytest.mark.parametrize("name", sorted(p.name for p in TEMPLATES.glob("*.md")))
def test_every_template_says_it_is_not_legal_advice_and_links_the_runbook(name):
    text = (TEMPLATES / name).read_text("utf-8")
    assert "not legal advice" in text
    assert "https://statechecksecurity.com/dpdpa/breach-runbook" in text
