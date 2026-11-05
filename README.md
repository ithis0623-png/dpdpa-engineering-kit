# DPDPA Engineering Kit

Tested code for India's Digital Personal Data Protection Act, 2023 and the DPDP Rules, 2025:
consent records, breach detection, encryption, data residency, CI/CD privacy gates and
control mappings. Each folder comes from one of
[StateCheck Security's articles](https://statechecksecurity.com/blog), which explain the
obligation behind the code.

> **Not legal advice.** This kit shows engineering patterns. Whether a pattern meets an
> obligation depends on your processing, your contracts and how the Data Protection Board
> reads the Rules. Have your counsel or DPO review your implementation.

## What's here

| Folder | What it does | DPDPA / Rules | Article |
|---|---|---|---|
| [`consent/`](consent/) | Consent schema (PostgreSQL), signed consent receipts, hash-chained audit log, a FastAPI grant endpoint | S.5, S.6, Rule 3, Rule 6(1)(c) | [Consent management API](https://statechecksecurity.com/blog/dpdpa-consent-management-api) |
| [`consent-manager/`](consent-manager/) | Zero-knowledge consent routing and an append-only consent ledger | S.6(7)–(9), Rule 4, First Schedule | [Consent Manager registration](https://statechecksecurity.com/blog/dpdpa-consent-manager-registration) |
| [`breach-notification/`](breach-notification/) | Splunk detection rule and a Section 2(u) breach classifier; the five breach runbook templates, an incident log model and a deadline calculator for Rule 7 and CERT-In | S.2(u), S.8(6), Rule 7 | [Breach notification automation](https://statechecksecurity.com/blog/dpdpa-breach-notification-automation), [Breach runbook](https://statechecksecurity.com/dpdpa/breach-runbook) |
| [`encryption/`](encryption/) | Field-level envelope encryption, nginx TLS, Istio mTLS, KMS on AWS / Azure / GCP, an OPA encryption gate | Rule 6(1)(a) | [Encryption requirements](https://statechecksecurity.com/blog/dpdpa-encryption-requirements) |
| [`cross-border/`](cross-border/) | India-residency SCP, S3 / KMS Terraform, Azure Policy, a GDPR + DPDPA transfer decision engine | S.16 | [Cross-border data transfer](https://statechecksecurity.com/blog/dpdpa-cross-border-data-transfer) |
| [`ci-cd/`](ci-cd/) | Three privacy gates for GitHub Actions (and GitLab): Semgrep rules, PII grep checks, IaC policies, an erasure-support check | S.8(4)–(5), Rule 6 | [Privacy by design in CI/CD](https://statechecksecurity.com/blog/dpdpa-privacy-by-design-cicd) |
| [`threat-modeling/`](threat-modeling/) | LINDDUN mitigations: enumeration-safe signup, purpose-scoped access policy, crypto-shredding | S.6(1), S.8(5), S.8(7) | [Threat modelling with LINDDUN and STRIDE](https://statechecksecurity.com/blog/dpdpa-threat-modeling-linddun-stride) |
| [`zero-trust/`](zero-trust/) | Least-privilege and micro-segmentation policies, a tamper-evident access log | Rule 6(1)(b)–(c) | [Zero Trust and DPDPA](https://statechecksecurity.com/blog/zero-trust-dpdpa-compliance) |
| [`rights-and-erasure/`](rights-and-erasure/) | Data Principal access and erasure service, erasure trigger evaluation | S.8(7)–(8), S.11–12, Rule 8 | [NIST Privacy Framework](https://statechecksecurity.com/blog/nist-privacy-framework-dpdpa), [SOC 2](https://statechecksecurity.com/blog/soc-2-dpdpa-compliance) |
| [`governance/`](governance/) | SDF governance config, data inventory and classification schemas, residency policy, roadmap formats | S.10, Rule 13 | [5-step roadmap](https://statechecksecurity.com/blog/5-step-dpdpa-implementation-roadmap), [NIST](https://statechecksecurity.com/blog/nist-privacy-framework-dpdpa) |
| [`mappings/`](mappings/) | ISO 27001:2022 ↔ DPDPA and SOC 2 TSC ↔ DPDPA crosswalks (CSV + XLSX) | — | [ISO 27001](https://statechecksecurity.com/blog/dpdpa-iso-27001-mapping), [SOC 2](https://statechecksecurity.com/blog/soc-2-dpdpa-compliance) |

[`CHANGES-FROM-ARTICLES.md`](CHANGES-FROM-ARTICLES.md) lists everything that changed
between an article's snippet and the code here, and why.

## How it is tested

Everything in the kit runs in CI on every push ([`.github/workflows/ci.yml`](.github/workflows/ci.yml)):

| What | How |
|---|---|
| Python | `ruff check`, `pytest`, including FastAPI endpoints through `TestClient` and AWS calls through botocore's `Stubber` |
| SQL | Each schema loaded into a fresh PostgreSQL 16 database, then a behaviour test (constraints, partitions, append-only triggers, role grants) |
| Rego | `opa fmt`, `opa check --strict`, `opa test` (OPA 1.10, Rego v1) |
| Terraform | `fmt -check`, `validate`, and `terraform test` against mocked providers, so no cloud account is needed |
| AWS IAM | Every condition key checked against AWS's [Service Reference](https://servicereference.us-east-1.amazonaws.com/) |
| nginx | The TLS config is loaded into nginx and probed: TLS 1.3 and TLS 1.2 AEAD accepted, CBC suites and TLS 1.1 refused |
| Semgrep | `semgrep --validate` and `semgrep --test` against an annotated fixture |
| Workflows, Istio, diagrams | `actionlint`, `istioctl validate`, Mermaid CLI render |
| Shell steps | The workflow's own grep steps are run against fixture repositories |

Not tested: the Splunk search runs only on Splunk, so its `.conf` structure is checked but
not its results. The GitLab pipeline is checked for structure and its shell step is run, but
GitLab's own linter needs a GitLab instance.

### Run it locally

```bash
python -m venv .venv && . .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt
ruff check .
pytest                       # add -m "not docker and not network" to skip those tests
```

The SQL, OPA, Terraform and Semgrep checks need those tools (or Docker); the CI workflow shows
the exact commands. `scripts/sql-tests.sh` runs the SQL suites against any PostgreSQL you
point the `PG*` variables at.

## Using the code

Copy what you need. Each folder's README says what to replace (keys, role ARNs, bucket names,
your data inventory) before the code is safe to run against real data. The Python modules
keep their collaborators (stores, KMS clients, queues) behind small interfaces with in-memory
versions for tests, so you can plug in your own.

## Licence

Code: [Apache License 2.0](LICENSE). The mappings in [`mappings/`](mappings/):
[CC BY 4.0](mappings/LICENSE). Please credit StateCheck Security when you reuse them.

## About

Maintained by [StateCheck Security](https://statechecksecurity.com), which does VAPT, source
code review, threat modelling and DPDPA compliance work for Indian companies. Questions and
fixes are welcome as issues or pull requests. To report a security problem in the kit, see
[SECURITY.md](SECURITY.md).
