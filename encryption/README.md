# Encryption

Rule 6(1)(a) lists encryption, obfuscation, masking and virtual tokens among the reasonable
security safeguards for personal data. This folder covers data in transit, at rest and in
application fields, plus a CI gate that checks Terraform plans.

From [DPDPA encryption requirements](https://statechecksecurity.com/blog/dpdpa-encryption-requirements).

| Path | What it is |
|---|---|
| `field_encryption.py` | Field-level AES-256-GCM with a fresh data key per record, wrapped by a KMS key; the ciphertext is bound to its field and Data Principal |
| `tls/nginx-tls.conf` | TLS 1.3 and TLS 1.2 AEAD-only, HSTS, OCSP stapling |
| `istio/mtls.yaml` | Mandatory mTLS in the `production` namespace |
| `terraform/aws` | KMS key with rotation, scoped key policy, deletion guard |
| `terraform/azure` | Key Vault (Premium, purge protection, firewall) with an HSM key and rotation |
| `terraform/gcp` | Cloud KMS HSM key ring in `asia-south1`, single-account IAM, Data Access logs |
| `policies/encryption.rego` | OPA gate for `terraform show -json`: S3 must use KMS, RDS/EBS/ElastiCache must be encrypted, RDS should use a customer-managed key |

## Before you use it

- **KMS client.** `DPDPAFieldEncryptor` expects `kms.encrypt(key_id, plaintext, encryption_context)`
  and `kms.decrypt(...)`. Wrap boto3 (`KeyId=`, `Plaintext=`, `EncryptionContext=`) or your
  provider's SDK.
- **Encryption context & pseudonyms.** Pass `pseudonym_key` (bytes) to `DPDPAFieldEncryptor` to
  HMAC the Data Principal ID into a pseudonym before sending it in the KMS encryption context,
  preventing cleartext personal data from appearing in CloudTrail audit logs.
  When upgrading a system with existing ciphertext, enable `legacy_context_fallback=True` to
  allow decrypting legacy records with the raw context on context mismatch (note: while enabled,
  legacy retries re-expose the raw ID in KMS audit logs). Run `rewrap_field(...)` on legacy records
  to re-encrypt them under the pseudonymized context, then disable `legacy_context_fallback`.
- **AWS audit logs.** The `kms_audit` log group needs a CloudTrail trail sending to it;
  CloudTrail's default event history keeps only 90 days.
- **TLS 1.3 everywhere.** Istio's minimum is TLS 1.2 until you set
  `meshConfig.meshMTLS.minProtocolVersion: TLSV1_3` (see the comment in `mtls.yaml`).
- **Customer-managed keys** are a policy choice for control over rotation, access and deletion.
  The DPDP Rules do not name a key type.

## Tests

`tests/test_field_encryption.py`, `tests/test_nginx_tls.py` (runs nginx in Docker and probes
the handshakes), `terraform test` in each `terraform/*` module, and `opa test policies/`.
