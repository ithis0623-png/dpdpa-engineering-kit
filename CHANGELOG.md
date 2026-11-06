# Changelog

All notable changes to the DPDPA Engineering Kit. Dates are UTC. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.1.0] - 2026-11-06

First tagged release. Everything here runs in CI on every push: Python (ruff, pytest),
SQL on PostgreSQL 16, Rego (OPA), Terraform with mocked providers, Semgrep rule tests,
and actionlint, istioctl and Mermaid checks.

### Added

- `consent/`: PostgreSQL consent schema, signed consent receipts, a hash-chained audit
  log and a FastAPI grant endpoint; withdrawal and withdrawal-parity endpoints with
  processor fan-out (#2); Rule 10 verifiable parental consent and the Fourth Schedule
  exemptions (#6).
- `consent-manager/`: zero-knowledge consent routing and an append-only consent ledger.
- `breach-notification/`: a Splunk detection rule and a Section 2(u) breach classifier;
  the five breach runbook templates, an incident log model and a deadline calculator for
  Rule 7 and CERT-In (#9); statutory Rule 7 notification formatters (#5).
- `encryption/`: field-level envelope encryption, nginx TLS, Istio mTLS, KMS on AWS,
  Azure and GCP, an OPA encryption gate; KMS encryption context pseudonymised so audit
  logs carry no cleartext personal data (#1).
- `cross-border/`: an India-residency SCP, S3 and KMS Terraform, Azure Policy, and a
  GDPR plus DPDPA transfer decision engine.
- `ci-cd/`: three privacy gates for GitHub Actions and GitLab: Semgrep rules, PII grep
  checks, IaC policies and an erasure-support check.
- `threat-modeling/`, `zero-trust/`, `mappings/`: LINDDUN mitigations, zero-trust
  policies and control mappings to ISO 27001, SOC 2 and NIST.
- `rights-and-erasure/`: Section 12 correction and Section 14 nomination services (#8).
- `governance/`: a statutory grievance redressal service with SLA tracking (#7).
- Community files: contributing guide, code of conduct, issue and PR templates (#4).

### Changed

- CI: TLS handshake wait before the nginx tests; quoted OPA directories; Windows Git
  Bash discovery consolidated into a shared conftest helper (#3).
- Docs: a DPO is required only for Significant Data Fiduciaries; Brazil added to the
  GDPR adequacy list.

### Related

- [dpdp-scan](https://github.com/statecheck-security/dpdp-scan) grew out of this kit's
  `ci-cd/` Semgrep rules and PII field list; it is the place those now evolve.

[0.1.0]: https://github.com/statecheck-security/dpdpa-engineering-kit/releases/tag/v0.1.0
