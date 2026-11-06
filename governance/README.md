# Governance and inventory

Configuration and record formats that the rest of the kit reads from: what data you hold and
why, how it is classified, where it may live, and what a Significant Data Fiduciary has to run
each year.

From [5-step DPDPA implementation roadmap](https://statechecksecurity.com/blog/5-step-dpdpa-implementation-roadmap),
[NIST Privacy Framework and DPDPA](https://statechecksecurity.com/blog/nist-privacy-framework-dpdpa),
[ISO 27001 and DPDPA](https://statechecksecurity.com/blog/dpdpa-iso-27001-mapping) and
[SOC 2 and DPDPA](https://statechecksecurity.com/blog/soc-2-dpdpa-compliance).

| File | What it is |
|---|---|
| `governance_config.py` | SDF governance settings: DPO, annual DPIA and audit, grievance handling |
| `data-inventory.yaml` | Processing inventory entry: data elements, purposes, processors, retention |
| `data-classification.yaml` | Classification tiers and the controls each one carries |
| `data-residency-policy.yaml` | Residency enforcement layers, pointing at the files in `../cross-border/` |
| `data-audit-item.json` | One line of a data audit (roadmap step 1) |
| `consent-record.sql` | Minimal consent table (roadmap step 2); `../consent/schema.sql` is the full version |
| `audit-log-entry.json` | Audit log record format (Rule 6(1)(c)) |
| `withdrawal-parity.txt` | Withdrawal takes the same steps as consent (Section 6(4)) |

### Grievance Redressal Service (Statutory Extension)

| File | What it is |
|---|---|
| `grievance_service.py` | Implements Section 13 & Rule 14 grievance lifecycle, configurable escalation (Grievance Officer / DPO), SLA monitoring within Rule 14(3) 90-day ceiling, and Section 13(3) DPBI complaint advisory |

## Before you use it

`governance_config.py` is set up for a Significant Data Fiduciary. If you are not notified as
one, Section 10's DPO, DPIA and audit duties don't apply, though a grievance process
(Section 8(10), Rule 14) still does.

## Tests

`tests/test_governance.py` checks the files parse and stay consistent with the Rules (grievance
response within Rule 14(3)'s 90 days, annual SDF cadences, the one-year log floor).
`tests/consent_record_test.sql` runs the consent table.
