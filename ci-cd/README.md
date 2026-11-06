# Privacy gates in CI/CD

Three gates that stop personal-data mistakes before they ship: code (Gate 1), infrastructure
(Gate 2) and deployment readiness (Gate 3).

From [Privacy by design in CI/CD](https://statechecksecurity.com/blog/dpdpa-privacy-by-design-cicd).

| Path | What it is |
|---|---|
| `github/dpdpa-privacy-checks.yml` | GitHub Actions workflow with all three gates; actions pinned to commit SHAs |
| `gitlab/gitlab-ci.yml` | The Gate 1 job for GitLab CI |
| `semgrep/dpdpa-rules.yml` | Semgrep rules: PII in logs, unencrypted PII model fields, `fields = '__all__'` serializers |
| `policies/retention.rego` | Gate 2: CloudWatch log groups keep logs for at least a year (Rules 6(1)(e), 8(3)) |
| `scripts/check_erasure_support.py`, `config/pii-fields.yaml` | Gate 3: every model with PII fields has an erasure method |
| `architecture.mmd`, `pipeline-flow.mmd` | Gate diagrams |

Gate 2 also uses `../encryption/policies/encryption.rego`.

**The Semgrep rules and `config/pii-fields.yaml` are kept here as the article's companion.** The versions that grow are in [dpdp-scan](https://github.com/statecheck-security/dpdp-scan): its rule pack adds JS/TS variants, personal data sent to analytics SDKs and date-of-birth collection without an age gate, and its field-name lexicon covers the Indian abbreviations and misspellings this list does not. For a new project, run dpdp-scan as Gate 1 instead of copying these.

## Using it

Copy the workflow to `.github/workflows/`, the Semgrep rules to `.semgrep/`, both Rego files
to `policies/dpdpa/`, and the script and config to `scripts/` and `config/`. The header of the
workflow lists the expected layout.

- **Gate 2** needs read-only cloud credentials for `terraform plan`; use OIDC rather than
  stored keys.
- **Gate 3** in the article also runs purpose-binding, retention and compliance-report
  scripts. They depend on your API spec and data model, so they aren't included; add them
  once written.
- **Grep checks** are a fast first pass, not a guarantee. The Semgrep rules catch more; neither
  replaces reviewing what your code logs.

## Tests

- `tests/test_workflow_gates.py` reads the workflow and runs its shell steps against fixture
  repositories.
- `tests/test_gitlab_pipeline.py` does the same for GitLab.
- `tests/test_check_erasure_support.py` covers the erasure check.
- `semgrep --test semgrep/` runs the rules against the annotated fixture `semgrep/dpdpa-rules.py`.
- `opa test policies/` runs the retention policy tests.
