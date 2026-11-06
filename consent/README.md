# Consent records

Evidence that a Data Principal saw a specific notice, in a specific language, and agreed to a
specific purpose: the core of what Section 6(10) asks a Data Fiduciary to prove.

From [Building a DPDPA consent management API](https://statechecksecurity.com/blog/dpdpa-consent-management-api)
and [SOC 2 and DPDPA](https://statechecksecurity.com/blog/soc-2-dpdpa-compliance).

| File | What it is |
|---|---|
| `schema.sql` | PostgreSQL schema: purposes, versioned notices with one translation per language, consent records bound to the notice version shown, a monthly-partitioned audit log, processor fan-out for erasure |
| `consent_receipt.py` | Builds and verifies an Ed25519-signed consent receipt |
| `audit_chain.py` | Hash-chain entry for each consent event, and `verify_chain()` to find the first edited or missing row |
| `grant_endpoint.py` | FastAPI `POST /v1/consents` (grant) and withdrawal parity endpoints `POST /v1/consents/{id}/withdraw` / `POST /v1/consents/withdraw`: atomic status checks, hash-chained audit logging, and cascading processor fan-out |
| `soc2-consent-audit-log.sql` | A simpler append-only consent log (SOC 2 P2.1 extension) enforced with role grants |
| `erd.mmd`, `lifecycle.mmd` | Entity and sequence diagrams |

### Child Data Protection (Statutory Extension)

| File | What it is |
|---|---|
| `parental_consent.py` | Implements Section 9 & Rule 10 verifiable parental consent, `ParentVerifier` interface, Fourth Schedule & Rule 12 statutory exemptions, multi-consent support, and consent withdrawal |

## Before you use it

- **Keys.** `Settings.signing_key` (Ed25519) and `pseudonym_key` (HMAC) belong in a KMS or
  vault. Rotating the signing key means keeping the old public key to verify old receipts.
- **Store.** `InMemoryConsentStore` is for tests. Implement `ConsentStore` against
  `schema.sql`, with `transaction()` mapped to a real database transaction.
- **Partitions.** `schema.sql` creates April 2026 only. Create the next month's partition ahead
  of time (pg_partman or a scheduled job); an insert with no matching partition fails.
- **Retention.** Rules 6(1)(e) and 8(3) set a one-year floor for logs. Keeping them longer
  needs a documented reason.
- **Roles.** For `soc2-consent-audit-log.sql`, the application role must not own the table.
  Grants don't bind the owner or a superuser; the trigger in `../consent-manager/ledger.sql` does.

## Tests

`tests/test_consent.py` (receipts, chain, endpoint, rollback) and the two `tests/*_test.sql`
files, run by `scripts/sql-tests.sh`.
