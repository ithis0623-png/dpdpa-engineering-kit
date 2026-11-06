## Description

Brief summary of the changes introduced in this PR.

## Statutory Ground

Which DPDPA 2023 Section or DPDP Rules 2025 provision does this address?
- [ ] Section 5 / Rule 3 (Notice & Language)
- [ ] Section 6 / Rule 4 (Consent & Withdrawal)
- [ ] Section 8 / Rule 6 (Security Safeguards & Erasure)
- [ ] Section 9 / Rule 10 (Child Data Protection & VPC)
- [ ] Section 10 / Rule 13 (Significant Data Fiduciary)
- [ ] Section 11 / 12 / 14 (Principal Rights: Access, Correction, Erasure, Nomination)
- [ ] Section 13 / Rule 14 (Grievance Redressal)
- [ ] Section 16 (Cross-Border Transfer)
- [ ] Other:

## Changes Proposed
- 

## Verification Checklist

- [ ] `ruff check .` passes without errors or warnings.
- [ ] `pytest -m "not docker and not network"` passes (all unit tests green).
- [ ] Added unit tests covering the new behavior / bug fix.
- [ ] Updated `CHANGES-FROM-ARTICLES.md` and/or module `README.md` if applicable.
- [ ] No real identifier anywhere in the change: fixtures use UIDAI test UIDs or generated synthetic values (`dpdp-scan .` is clean or only reports synthetic values).
- [ ] Every cited section or Rule is exact, and no text gives a compliance verdict.
- [ ] Commits are signed off (`git commit -s`, Developer Certificate of Origin).
