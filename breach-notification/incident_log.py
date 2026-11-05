"""
incident_log.py
Template (e) of the personal data breach runbook: one log per incident, a header and one entry
for every action, decision or message. https://statechecksecurity.com/dpdpa/breach-runbook

The log is your evidence. The detailed Board report must include a report on the intimations
given to affected Data Principals (Rule 7(2)(b)(vi)), and when setting a penalty the Board weighs
whether you mitigated the breach, and how quickly and how well (DPDP Act S.33(2)(e)).
Keep a copy outside the affected systems.
"""

from collections import Counter
from datetime import datetime
from enum import Enum

from pydantic import AwareDatetime, BaseModel, Field, model_validator


class Recipient(str, Enum):
    DATA_PRINCIPALS = "data_principals"  # Rule 7(1)
    BOARD = "board"                      # Rule 7(2)(a) and (b)
    CERT_IN = "cert_in"                  # CERT-In Directions of 28 April 2022, direction (ii)
    DATA_FIDUCIARY = "data_fiduciary"    # when you are the processor: tell your client (S.8(6) is theirs)


class Decision(BaseModel):
    # The runbook's six first decisions: in scope, S.2(u) breach, whose data, processor,
    # CERT-In, longer period. Write each answer down with the time and who decided.
    number: int = Field(ge=1, le=6)
    answer: str
    decided_at: AwareDatetime
    decided_by: str


class Message(BaseModel):
    to: Recipient
    channel: str            # e.g. "user account", "registered email", "Board portal", "incident@cert-in.org.in"
    reference: str | None = None
    recipients: int = Field(default=1, ge=1)
    failed: int = Field(default=0, ge=0)


class Entry(BaseModel):
    at: AwareDatetime
    who: str
    what: str
    decision: str | None = None
    evidence: str | None = None   # where it is saved, and its hash
    message: Message | None = None
    next_action: str | None = None


class IncidentLog(BaseModel):
    incident_id: str
    noticed_at: AwareDatetime | None = None   # N: CERT-In's 6-hour clock runs from here
    aware_at: AwareDatetime                   # T: both Rule 7 clocks run from here
    incident_lead: str
    deputy: str | None = None
    decisions: list[Decision] = []
    entries: list[Entry] = []

    @model_validator(mode="after")
    def entries_in_time_order(self):
        times = [e.at for e in self.entries]
        if times != sorted(times):
            raise ValueError("log entries must be in time order")
        return self

    def intimation_report(self) -> dict:
        """The figures for Rule 7(2)(b)(vi): messages to affected Data Principals, by channel."""
        sent: Counter = Counter()
        failed: Counter = Counter()
        first: datetime | None = None
        for e in self.entries:
            if e.message and e.message.to is Recipient.DATA_PRINCIPALS:
                sent[e.message.channel] += e.message.recipients
                failed[e.message.channel] += e.message.failed
                first = first or e.at
        return {
            "messages_sent": sum(sent.values()),  # a resend to the same person counts again
            "failed": sum(failed.values()),
            "by_channel": {ch: {"sent": n, "failed": failed[ch]} for ch, n in sent.items()},
            "first_sent_at": first.isoformat() if first else None,
        }
