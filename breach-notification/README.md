# Breach notification

Detect incidents that touch personal data, decide whether they are a personal data breach under
Section 2(u), and start the two Rule 7 clocks.

From [Automating DPDPA breach notification](https://statechecksecurity.com/blog/dpdpa-breach-notification-automation)
and [DPDP Act 2023: data breach duties](https://statechecksecurity.com/blog/dpdp-act-2023-india).

| File | What it is |
|---|---|
| `savedsearches.conf` | Splunk correlation search that tags security events on assets holding personal data and sends them to a SOAR webhook |
| `breach_classifier.py` | Applies the Section 2(u) test: personal data involved, not authorised, and a recognised breach type, or escalate for human review. (`ESCALATE_TO_DPO` means whoever owns privacy decisions; only a Significant Data Fiduciary must appoint a DPO, under Section 10(2)(a).) |
| `notification_formatter.py` | Builds statutory intimations under Rule 7: Rule 7(1) to affected Data Principals, Rule 7(2)(a) first intimation to the Board, and Rule 7(2)(b) 72-hour detailed report with (i)–(vi) |
| `pipeline.txt` | The notification pipeline, from SIEM to the detailed Board report within 72 hours |
| `nist-breach-workflow.mmd` | The same workflow, mapped to the NIST Privacy Framework |

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
