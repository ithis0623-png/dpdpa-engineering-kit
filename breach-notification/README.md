# Breach notification

Detect incidents that touch personal data, decide whether they are a personal data breach under
Section 2(u), and start the two Rule 7 clocks.

From [Automating DPDPA breach notification](https://statechecksecurity.com/blog/dpdpa-breach-notification-automation)
and [DPDP Act 2023: data breach duties](https://statechecksecurity.com/blog/dpdp-act-2023-india). The templates,
incident log and deadline calculator come from the [personal data breach runbook](https://statechecksecurity.com/dpdpa/breach-runbook).

| File | What it is |
|---|---|
| `savedsearches.conf` | Splunk correlation search that tags security events on assets holding personal data and sends them to a SOAR webhook |
| `breach_classifier.py` | Applies the Section 2(u) test: personal data involved, not authorised, and a recognised breach type, or escalate for human review. (`ESCALATE_TO_DPO` means whoever owns privacy decisions; only a Significant Data Fiduciary must appoint a DPO, under Section 10(2)(a).) |
| `notification_formatter.py` | Builds statutory intimations under Rule 7: Rule 7(1) to affected Data Principals, Rule 7(2)(a) first intimation to the Board, and Rule 7(2)(b) 72-hour detailed report with (i)–(vi) |
| `pipeline.txt` | The notification pipeline, from SIEM to the detailed Board report within 72 hours |
| `nist-breach-workflow.mmd` | The same workflow, mapped to the NIST Privacy Framework |

## Breach runbook companion

What to send, and by when, once you are aware of a personal data breach. The
[runbook](https://statechecksecurity.com/dpdpa/breach-runbook) explains the roles, the first
decisions and the hour-by-hour plan; these files are the parts you copy.

| File | What it is |
|---|---|
| `templates/a-data-principal-intimation.md` | Message to each affected person, one paragraph per Rule 7(1)(a)–(e) item |
| `templates/b-board-first-intimation.md` | First intimation to the Board, the five Rule 7(2)(a) items |
| `templates/c-board-detailed-report.md` | Detailed Board report, the six Rule 7(2)(b) headings |
| `templates/d-board-longer-period-request.md` | Written request for a longer period under Rule 7(2)(b) |
| `templates/e-incident-log.example.json` | A filled-in incident log, in the shape `incident_log.py` validates |
| `incident_log.py` | Pydantic model for the log: N and T, the first decisions, time-ordered entries, and `intimation_report()` for the figures Rule 7(2)(b)(vi) asks for |
| `breach_deadlines.py` | Every deadline from N (noticed) and T (aware): CERT-In's 6 hours from N, the 72-hour detailed Board report from T (or the longer period the Board allows), and the runbook's hour-48 check. The first intimations are "without delay" and get no due time |

The templates are starting points, **not legal advice**: have your final versions reviewed.
CERT-In's 6-hour report comes from its Directions of 28 April 2022 under the IT Act, 2000, not
the DPDP Act; CERT-In's FAQ (Q30) says any data breach or data leak is one to report within 6
hours. Rule 7 applies from 13 May 2027 (Rule 1(4)). Runtime: `pydantic` for `incident_log.py`;
`breach_deadlines.py` uses the standard library only.

## Before you use it

- **Lookup.** The search expects a `pii_asset_inventory.csv` lookup with `asset_id`,
  `contains_personal_data`, `data_classes` and `data_principal_count`. Build it from your data
  inventory (see `../governance/data-inventory.yaml`).
- **Thresholds.** `event_count > 5` over 15 minutes is a starting point; tune it to your logs.
- **Other SIEMs.** The logic ports to Sentinel (KQL), QRadar (AQL) or Elastic; keep the action
  names in step with `ACTION_MAP` in the classifier.
- **Rule 7.** The classifier only decides whether there is a breach. The intimation to each
  affected Data Principal and the initial intimation to the Board go "without delay"; the
  detailed report to the Board within 72 hours (Rule 7(2)(b)).

## Tests

`tests/test_breach_notification.py`: the classifier's gates, agreement between the SIEM action
names and the classifier, and the `.conf` structure. The search itself only runs on Splunk.

`tests/test_runbook_companion.py`: the deadline arithmetic (CERT-In from N, 72 hours from T, a
longer period replacing it, timezone-less times refused), the example log against the model and
its own deadlines, and that every template carries every Rule 7 item it should.
