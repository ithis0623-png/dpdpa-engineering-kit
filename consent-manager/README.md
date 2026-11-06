# Consent Manager

Patterns for a Consent Manager registered under Rule 4: routing consent and data-sharing
instructions without being able to read the personal data, and keeping an append-only record.

From [Consent Manager registration under the DPDP Rules](https://statechecksecurity.com/blog/dpdpa-consent-manager-registration).

| File | What it is |
|---|---|
| `consent_router.py` | Routes encrypted consent grant, withdrawal, and data-sharing tokens between fiduciaries, storing only their SHA-256 hashes (First Schedule, Part B, Item 2) |
| `ledger.sql` | PostgreSQL consent event store; triggers refuse `UPDATE`, `DELETE` and `TRUNCATE` |
| `export-schema.yaml` | Example machine-readable export of a Data Principal's consent records |
| `architecture.mmd` | Zero-knowledge architecture diagram |

## Before you use it

- The router stores `principal_id`, the Consent Manager's own account identifier. It never
  sees the payload, but it does know who the Data Principal is; that is unavoidable for a
  Consent Manager and should be covered in its own notice.
- End-to-end encryption between Data Principal and fiduciary is yours to provide; the router
  only assumes the bytes it gets are ciphertext.
- Superusers can still disable triggers. Restrict who has superuser on the ledger database
  and log it.

## Tests

`tests/test_consent_manager.py` and `tests/ledger_test.sql`.
