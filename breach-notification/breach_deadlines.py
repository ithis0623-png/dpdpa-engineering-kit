"""
breach_deadlines.py
Every deadline the personal data breach runbook tracks, from two timestamps:
N, when the cyber incident was first noticed, and T, when you became aware of a personal data
breach. https://statechecksecurity.com/dpdpa/breach-runbook

Only two of these are hour counts in law: CERT-In's 6 hours (IT Act, 2000, not the DPDP Act)
and the 72 hours for the detailed Board report (Rule 7(2)(b)). The first intimations to each
affected person and to the Board are "without delay" (Rule 7(1), Rule 7(2)(a)), which has no
fixed hour, so they get no due time here: send them as soon as you can, not at a deadline.
The hour-48 check is the runbook's own target, not the law.
"""

from dataclasses import dataclass
from datetime import datetime, timedelta

CERT_IN_REPORT = timedelta(hours=6)        # CERT-In Directions of 28 April 2022, direction (ii)
DETAILED_BOARD_REPORT = timedelta(hours=72)  # DPDP Rules 2025, Rule 7(2)(b)
LONGER_PERIOD_CHECK = timedelta(hours=48)  # runbook target: decide whether to ask the Board for more time


@dataclass(frozen=True)
class Deadline:
    key: str
    what: str
    due: datetime | None   # None: "without delay", no fixed hour
    basis: str
    in_law: bool            # False for the runbook's own targets


def _aware(name: str, value: datetime | None) -> None:
    if value is not None and value.tzinfo is None:
        raise ValueError(f"{name} must carry a timezone: deadlines across a day boundary are ambiguous without one")


def breach_deadlines(
    aware_at: datetime,
    noticed_at: datetime | None = None,
    cert_in_applies: bool = False,
    board_allowed_until: datetime | None = None,
) -> list[Deadline]:
    """
    aware_at: T, when your written "aware" trigger was met. Both Rule 7 clocks start here.
    noticed_at: N, when the cyber incident was first noticed. CERT-In's clock starts here.
    cert_in_applies: the incident is one CERT-In expects reported within 6 hours (Annexure I,
        read with CERT-In's FAQ Q30: any data breach or data leak qualifies).
    board_allowed_until: a longer period the Board has allowed on a written request.
    """
    _aware("aware_at", aware_at)
    _aware("noticed_at", noticed_at)
    _aware("board_allowed_until", board_allowed_until)
    if cert_in_applies and noticed_at is None:
        raise ValueError("a CERT-In report runs from when the incident was noticed: pass noticed_at")

    detailed_due = aware_at + DETAILED_BOARD_REPORT
    if board_allowed_until is not None:
        if board_allowed_until <= detailed_due:
            raise ValueError("board_allowed_until must be later than the 72-hour deadline it extends")
        detailed_due = board_allowed_until

    deadlines = []
    if cert_in_applies:
        deadlines.append(Deadline(
            "cert_in", "Report the incident to CERT-In", noticed_at + CERT_IN_REPORT,
            "CERT-In Directions, 28 April 2022, direction (ii): within 6 hours of noticing it", True))
    deadlines += [
        Deadline("data_principals", "Intimate each affected Data Principal (template a)", None,
                 "DPDP Rules 2025, Rule 7(1): without delay", True),
        Deadline("board_first", "First intimation to the Board (template b)", None,
                 "DPDP Rules 2025, Rule 7(2)(a): without delay", True),
    ]
    if board_allowed_until is None:
        deadlines.append(Deadline(
            "longer_period_check", "Decide whether to ask the Board for more time (template d)",
            aware_at + LONGER_PERIOD_CHECK, "Runbook target; the request must reach the Board before the 72 hours end",
            False))
    deadlines.append(Deadline(
        "board_detailed", "Detailed report to the Board (template c)", detailed_due,
        "DPDP Rules 2025, Rule 7(2)(b): within 72 hours of becoming aware, or a longer period the Board allows",
        True))
    return deadlines


def overdue(deadlines: list[Deadline], now: datetime) -> list[Deadline]:
    """Deadlines with a due time that has passed. "Without delay" items are never listed: they are due now."""
    _aware("now", now)
    return [d for d in deadlines if d.due is not None and d.due < now]
