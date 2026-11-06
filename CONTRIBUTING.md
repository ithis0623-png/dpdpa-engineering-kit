# Contributing to the DPDPA Engineering Kit

Thank you for your interest in contributing to the **DPDPA Engineering Kit**! This repository provides open-source, tested engineering implementations for India's **Digital Personal Data Protection Act, 2023 (DPDPA)** and the **DPDP Rules, 2025**.

Contributions from software engineers, privacy engineers, security researchers, and legal engineers are welcome.

---

## Code of Conduct

All contributors and participants are expected to adhere to the [Code of Conduct](CODE_OF_CONDUCT.md). Please treat everyone with respect, professionalism, and empathy.

---

## Core Guiding Principles

1. **Statutory Alignment**: Every module, schema, and API endpoint must trace to a specific statutory obligation in the DPDP Act, 2023 or the DPDP Rules, 2025.
2. **Minimalism & Simplicity**: Avoid over-engineering or unnecessary external dependencies. Prefer the standard library and well-established cryptographic primitives (`cryptography`, `pydantic`, `fastapi`).
3. **Burden of Proof & Non-Repudiation**: Consent and audit systems must produce cryptographically verifiable evidence (hash-chained logs, signed receipts) without logging cleartext personal data.
4. **Test-First Discipline**: Every change, feature, or bug fix must be accompanied by comprehensive tests and pass `ruff check .`.
5. **Synthetic data only**: fixtures, tests, examples and docs never contain a real identifier. Aadhaar-shaped values come from UIDAI's published test range or are generated with a valid Verhoeff check digit; PANs, GSTINs, phone numbers and email addresses are made up. Run [dpdp-scan](https://github.com/statecheck-security/dpdp-scan) over your branch before opening a PR; its allowlist knows the UIDAI test UIDs.
6. **Legal wording is reviewed, not improvised**: any text that cites a section of the Act or a Rule, in code comments, messages, READMEs or templates, is checked against the notified texts. State the exact provision (`S.8(5)`, `Rule 6(1)(a)`), never a paraphrase of what the law "requires", and never a compliance verdict. A maintainer runs the legal-accuracy check used across StateCheck's DPDPA material before merging; expect wording changes.

---

## Development Setup

### Prerequisites
- Python 3.12+
- Git

### 1. Clone & Setup Environment

```bash
git clone https://github.com/statecheck-security/dpdpa-engineering-kit.git
cd dpdpa-engineering-kit

# Create and activate virtual environment
python -m venv .venv
source .venv/bin/activate       # Linux / macOS
# .venv\Scripts\activate        # Windows

# Install development & test dependencies
pip install -r requirements-dev.txt
```

### 2. Running Quality Gates

Before opening a pull request or pushing changes, ensure all checks pass:

```bash
# 1. Lint and format checks
ruff check .

# 2. Run the unit test suite (excludes Docker and external network calls)
pytest -m "not docker and not network"

# 3. Run full test suite (if Docker is running locally)
pytest
```

---

## Pull Request Guidelines

1. **Fork and Branch**: Create a feature or fix branch from `main` (e.g., `git checkout -b fix/kms-context`).
2. **Atomic Commits**: Keep PRs focused on a single change with clear, descriptive commit messages following Conventional Commits (e.g., `feat:`, `fix:`, `docs:`, `test:`).
3. **Include Tests**: Add unit tests in the appropriate module's `tests/` directory.
4. **Update Documentation**: If adding a new feature or fixing an article divergence, update `CHANGES-FROM-ARTICLES.md` and the relevant README.
5. **Open PR**: Submit your pull request to `statecheck-security/dpdpa-engineering-kit` with a clear description referencing the relevant statutory sections.
6. **Sign off your commits** (`git commit -s`): the [Developer Certificate of Origin](https://developercertificate.org/) is how you confirm you have the right to contribute the code under Apache-2.0. PRs without a sign-off are asked to add one before review.
7. **Expect a review of the legal text and the data**: maintainers check every cited provision and every fixture value (principles 5 and 6). A PR that adds a whole service or a new dependency takes longer than a fix; say in the description why the dependency is needed.
