# Changes from the articles

The code in this kit started as the snippets in StateCheck Security's DPDPA articles.
Testing them turned up the problems below. Each one is fixed here and covered by a test,
so the kit, not the article, is the version to copy. Until the articles are updated they
still show the original snippets.

**Severity:** *Breaks* = fails to load, parse or apply. *Wrong* = runs but does something
other than what the article says. *Misleading* = a comment or claim that isn't true.
*Hygiene* = works, but would not pass a careful review.

## Consent management API (`/blog/dpdpa-consent-management-api`) → `consent/`

| Severity | Problem | Fix | Verified by |
|---|---|---|---|
| Breaks | `consent_audit_event` is partitioned by `occurred_at`, but its primary key is `event_id` alone. PostgreSQL rejects this: *unique constraint on partitioned table must include all partitioning columns*. | `PRIMARY KEY (event_id, occurred_at)` | `consent/tests/schema_test.sql` on PostgreSQL 16 |
| Wrong | The grant handler calls `now()` twice, once for the signed receipt and once for the stored record, so the evidence can disagree with what was signed. | One timestamp for both. | `test_grant_returns_verifiable_receipt_and_chained_events` |
| Hygiene | Content hash compared with `!=`. | `hmac.compare_digest`. | — |

## Consent Manager registration (`/blog/dpdpa-consent-manager-registration`) → `consent-manager/`

| Severity | Problem | Fix | Verified by |
|---|---|---|---|
| Wrong | The "append-only" ledger blocks `UPDATE` and `DELETE` with a row trigger, but `TRUNCATE` skips row triggers and empties the table. | Statement-level `BEFORE TRUNCATE` trigger. | `consent-manager/tests/ledger_test.sql` |

## Breach notification automation (`/blog/dpdpa-breach-notification-automation`) → `breach-notification/`

| Severity | Problem | Fix | Verified by |
|---|---|---|---|
| Breaks | The Splunk rule has `#` comments inside the multi-line `search =` value and no `\` line continuations. `.conf` files only allow whole-line comments, so this is not a valid `savedsearches.conf`. The webhook action is also never enabled. | Backslash continuations, SPL ```` ``` ```` comments, `action.webhook = 1`, a schedule. | `test_savedsearch_is_valid_conf_and_matches_the_classifier` (the original fails at line 11) |
| Wrong | The SIEM rule emits `DataExfiltration`, `DataModification`, … but the classifier only knows `exfiltration`, `data_modification`, … so every real alert falls through to "escalate to DPO". | SIEM action names added to `ACTION_MAP`. | `test_every_siem_action_is_classified_without_escalation` |
| Hygiene | Unused imports. | Removed. | ruff |

## Encryption requirements (`/blog/dpdpa-encryption-requirements`) → `encryption/`

| Severity | Problem | Fix | Verified by |
|---|---|---|---|
| Breaks | `encryption.rego` does not parse in any OPA version: Rego has no implicit string concatenation (`"a " "b"` inside `sprintf`), and the rules use pre-1.0 syntax. | Rego v1 syntax, single strings. Merged with the privacy-by-design version (below). | `opa check --strict`, 12 `opa test` cases |
| Wrong | Rego `not x` is true only when `x` is undefined or false. Terraform plan JSON writes unset attributes as `null`, so `storage_encrypted: null`, `encrypted: null` and `kms_key_id: null` slipped through. | `is_true()` / `has_value()` helpers. | `test_null_booleans_are_treated_as_off`, `test_rds_with_default_key_is_denied` |
| Misleading | Two deny messages say DPDPA "requires" customer-managed keys / "encryption with managed keys". Rule 6(1)(a) lists encryption among reasonable safeguards; it names no key type. | Messages now state the rule as written and label the CMK check as a policy choice. | review |
| Breaks | `aws_kms_dpdpa.tf` references `data.aws_caller_identity.current` and three variables it never declares, so `terraform validate` fails. Same for the Azure and GCP files. | `versions.tf` and `variables.tf` per module. | `terraform validate` + `terraform test` (mocked providers) |
| Wrong | `kms:DescribeKey` sits in the statement conditioned on `kms:EncryptionContext:purpose`. DescribeKey carries no encryption context, so the condition never matches and the apps can never call it. | Separate `ApplicationDescribeKey` statement. | `encryption/terraform/aws/tests/kms.tftest.hcl`; AWS Service Reference lists no context key for DescribeKey |
| Hygiene | Azure diagnostic setting uses the deprecated `metric` block (removed in azurerm v5). | `enabled_metric`. | `terraform validate` (no warnings) |
| Misleading | nginx comment: "the only three cipher suites in TLS 1.3". TLS 1.3 defines five. The config also leaves out `TLS_AES_128_GCM_SHA256`, which RFC 8446 makes mandatory to implement, while the comment calls it "acceptable". | Comment corrected; the suite is enabled. | `encryption/tests/test_nginx_tls.py` runs nginx and checks TLS 1.3 / TLS 1.2 AEAD accepted, CBC and TLS 1.1 refused |
| Misleading | Istio header: "Enforces TLS 1.3 between all services". PeerAuthentication + DestinationRule make mTLS mandatory; Istio's minimum stays TLS 1.2 unless `meshMTLS.minProtocolVersion` is set. | Comment corrected, with the setting that does enforce 1.3. | `istioctl validate` |
| Misleading | `dek = b'\x00' * len(dek)` "zeroes out the plaintext DEK from memory". Python bytes are immutable; this binds a new object and leaves the key where it was. | Honest comment, `del dek`, and a pointer to doing key handling in KMS. | review |
| Wrong | `field_encryption.py` puts the Data Principal ID in the KMS encryption context. CloudTrail logs the context in plain text, leaking personal data into immutable audit logs. | `pseudonym_key` HMACs the principal ID before passing it to KMS; fallback to raw ID on decrypt transparently migrates legacy records. | `test_pseudonymized_kms_context_prevents_cleartext_pii_in_cloudtrail`, `test_fallback_decrypt_for_legacy_unpseudonymized_records` |

## Cross-border data transfer (`/blog/dpdpa-cross-border-data-transfer`) → `cross-border/`

| Severity | Problem | Fix | Verified by |
|---|---|---|---|
| Wrong | The bucket policy and the SCP condition on `s3:ReplicationDestinationBucket` and `rds:CopyDestinationRegion`. Neither key exists. A Deny with `StringNotEquals`/`StringNotLike` on a missing key applies to every request, so the policies block *all* replication setup and *all* snapshot copies, including those that stay in India. | SCP denies regional actions outside `ap-south-1`/`ap-south-2` via `aws:RequestedRegion` (for a cross-region copy, that is the destination region); replication setup limited to a residency-admin role via `aws:PrincipalArn`. | `test_aws_condition_keys.py` checks every key in the kit against AWS's Service Reference, and confirms the two original keys are absent |
| Breaks | `residency.tf` uses `provider = aws.ap_south_1` and `data.aws_caller_identity.current` without declaring either. | Declared in `versions.tf`. | `terraform validate` + `terraform test` |
| Misleading | "Data encrypted with this key cannot be decrypted outside the region" holds only for single-Region keys. | `multi_region = false`, asserted in the test. | `kms_key_cannot_leave_the_region` |

## Privacy by design in CI/CD (`/blog/dpdpa-privacy-by-design-cicd`) → `ci-cd/`

| Severity | Problem | Fix | Verified by |
|---|---|---|---|
| Wrong | Aadhaar regex `[0-9]{4}[\s-][0-9]{4}…`: inside `[...]`, `\s` is a literal backslash or `s`, so `2345 6789 0123` is not matched. | `[[:space:]-]` plus word boundaries. | `test_article_regex_missed_space_separated_aadhaar` runs both versions |
| Wrong | Semgrep rule `dpdpa-unencrypted-pii-storage` matches `$MODEL.$FIELD = models.CharField(...)`, but Django declares `email = models.CharField(...)` in the class body, so it never fires. Its `metavariable-regex` sits outside `patterns` and is unanchored (`company` matches `pan`). | `pattern-inside` the class, `patterns:` list, anchored regex. | `semgrep --test` fixture: the original rules flag 0 of the expected lines for 2 of 3 rules; the fixed rules pass 3/3 |
| Wrong | Semgrep rule `dpdpa-excessive-data-collection` targets `serializers.Serializer`, which has no `Meta.fields`. | `serializers.ModelSerializer`. | same |
| Breaks | Gate 2 queries `data.dpdpa.deny`, a rule that doesn't exist; its first `opa eval` exits 0 whatever it finds; Terraform is never installed; `retention.rego` is referenced but never given; the `cd infrastructure/` makes the `policies/` path wrong. | `setup-terraform`, pinned OPA, one `--fail-defined` query over every `data.dpdpa.*.deny`, `retention.rego` written and tested. | OPA run against a failing and a passing plan; `retention_test.rego` |
| Breaks | Gate 3 calls `check_purpose_bindings.py`, `validate_retention.py` and `generate_compliance_report.py`, which the article never provides, and reads `sast-results.json` / `iac-results.json` that no earlier job produces. | Kept only the step whose script exists; the others are listed as yours to write. | `test_gate3_runs_the_kits_erasure_script` |
| Hygiene | `returntocorp/semgrep-action` redirects to `semgrep/semgrep-action`, which is archived. `trufflehog@main` tracks a moving branch. | Semgrep container; every action pinned to a commit SHA. | `test_every_action_is_pinned_to_a_commit`, actionlint |
| Wrong | GitLab job uploads Semgrep's `--json` output as `reports:sast`, which only accepts GitLab's SAST schema. Its grep alternations are unbracketed, so `log.*aadhaar\|aadhar\|pan_number` matches any line containing `aadhar`. | `--gitlab-sast`; same grouped patterns as the GitHub workflow. | `ci-cd/tests/test_gitlab_pipeline.py` |
| Wrong | `check_erasure_support.py` only looks at `x = ...` assignments, so dataclass, Pydantic and SQLAlchemy 2.0 models (`email: Mapped[str] = …`) pass unchecked. | Also reads annotated assignments. | `test_annotated_fields_are_checked` |
| Breaks | The privacy-by-design `encryption.rego` has the same parse error as above, and checks `aws_s3_bucket.server_side_encryption_configuration`, which AWS provider v4+ moved to its own resource. On a current provider the attribute is unknown at plan time, so the check flags every bucket being created. | Merged into `encryption/policies/encryption.rego`, which checks `aws_s3_bucket_server_side_encryption_configuration`. | `opa test` |

## Threat modelling with LINDDUN and STRIDE (`/blog/dpdpa-threat-modeling-linddun-stride`) → `threat-modeling/`

| Severity | Problem | Fix | Verified by |
|---|---|---|---|
| Breaks | `purpose_scope.rego` has the same implicit string concatenation, and `violation[msg] if` without `contains` is not a set rule in OPA 1.x. | Fixed. | 7 `opa test` cases |
| Misleading | `hmac.compare_digest(correlation_id, correlation_id)` "neutralises timing oracles". Comparing a value with itself does no useful work; the asynchronous enqueue is what removes the timing signal. | Line removed; the comment now says what does the work. | review |
| Wrong | Email and phone are HMAC'd as typed, so `Asha@Example.in` and `asha@example.in`, or `+91 98765 43210` and `09876543210`, become different people. | Normalised before hashing. | `test_same_person_gets_the_same_hmac` |
| Breaks | `crypto_shred.py` creates boto3 clients at import time; `boto3.client("kms")` raises `NoRegionError` on import wherever no default region is set. | Clients passed in. | botocore Stubber tests |

## Zero Trust (`/blog/zero-trust-dpdpa-compliance`) → `zero-trust/`

| Severity | Problem | Fix | Verified by |
|---|---|---|---|
| Wrong | The audit event's "integrity seal" is a SHA-256 of the event. Anyone who can edit the log line can recompute it, so it proves nothing. | HMAC with a key the writer holds, chained to the previous event; `verify_log()`. | `test_attacker_without_key_cannot_reseal`, `test_deleted_event_is_detected` |

## SOC 2 and DPDPA (`/blog/soc-2-dpdpa-compliance`) → `consent/`, `rights-and-erasure/`

| Severity | Problem | Fix | Verified by |
|---|---|---|---|
| Breaks | `REVOKE … FROM app_service_role` fails when the role doesn't exist, and revoking privileges the role never had makes nothing immutable. | Explicit `GRANT SELECT, INSERT`, `REVOKE` incl. `TRUNCATE`, with the owner caveat. | `consent/tests/soc2_audit_log_test.sql`, run as the app role |
| Wrong | The erasure service defaults *every* purpose to a three-year inactivity period, though its own comment says the Third Schedule period applies only to the listed large platforms. | No inactivity trigger unless a period is configured; the trigger flags the Rule 8(2) 48-hour notice. | `test_purpose_without_a_prescribed_period_never_expires_on_inactivity` |

## NIST Privacy Framework (`/blog/nist-privacy-framework-dpdpa`) → `rights-and-erasure/`, `governance/`

| Severity | Problem | Fix | Verified by |
|---|---|---|---|
| Misleading | "Private methods omitted … see full implementation in the StateCheck DPDPA Toolkit (open-source, coming Q3 2026)". That date has passed. | Implemented here against a `DataInventory` interface. Update the article to link this repository. | `test_rights_and_erasure.py` |
| Wrong | An erasure that a legal hold partly blocked is reported as `completed`. | `partially_completed`. | `test_erasure_respects_legal_holds_and_says_so` |

## ISO 27001 mapping (`/blog/dpdpa-iso-27001-mapping`) → `mappings/`, `governance/`

| Severity | Problem | Fix | Verified by |
|---|---|---|---|
| Wrong | In the downloadable CSV and XLSX, row 15 (Section 10(2)(c)(i), DPIA) is split by an unquoted comma: half of Implementation Notes lands in Technical Patterns and every later column shifts. In the XLSX the Effort value is lost. | Row merged in both files; Effort restored from the CSV (`Medium`). The CSV diff is that one line. | `test_csv_and_xlsx_hold_the_same_rows` |
| Wrong | The `personal_data_dpdpa` classification tier drops `integrity_check`, which every lower tier has. Alteration of personal data is a breach under Section 2(u). | Added. | `test_personal_data_tier_carries_the_dpdpa_controls` |

## Known limits, not changed

- `encryption/terraform/aws/kms.tf` creates a CloudWatch log group "for KMS audit" but no CloudTrail trail feeds it. CloudTrail event history alone keeps 90 days, not the year Rule 6(1)(e) asks for. Add a trail to your logging account.
- `crypto_shred.py` uses one KMS key per Data Principal. KMS bills per key per month, so at scale, wrap per-principal data keys with one KMS key and delete the wrapped key instead. A scheduled key deletion can be cancelled for 7 days; record the erasure as final only after KMS emits `DeleteKey`.
- `transfer-policy.json` leaves the US off the GDPR adequacy list on purpose: the EU–US Data Privacy Framework covers only certified organisations, which a country list can't express.
