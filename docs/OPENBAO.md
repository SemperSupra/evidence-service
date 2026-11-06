# OpenBao Transit adapter — bounded RDT&E

The source-safe `pkg/transitclient` adapter calls the existing OpenBao
Transit `encrypt`, `decrypt`, and `rewrap` API for one 32-byte DEK at a
time. It does **not** start OpenBao, provision tokens or keys, manage signing
keys, seal packet evidence, authorize callers, or claim a real-vault recovery
drill. Unit tests use a localhost synthetic HTTP mock, never service credentials.

## Contract and security invariants

- A separately provisioned Transit key **must** be `derived=true`,
  `convergent_encryption=false`, `exportable=false`, with plaintext backups
  disabled. Each operation supplies a nonempty, stable, unique, session+artifact
  derivation context; using different scopes must not recover the same DEK.
- Restrict the wrapping worker token to **update-only** on the intended
  `transit/encrypt/<key>`, `transit/decrypt/<key>` and
  `transit/rewrap/<key>` operations. Token must not create keys or access
  Transit management/export paths. In future, separately scope unwrap to a
  custodian-approved worker. Enable and secure OpenBao audit devices.
- External traffic requires HTTPS with certificate validation; raw HTTP is
  accepted only for IP-literal loopback tests. Redirects are never followed.
- No raw key, ciphertext, HTTP response body, token, or payload is included in
  returned error messages. Responses have a bounded size; any failure denies
  the operation. Avoid logging bodies at proxies or gateways.
- `rewrap` changes key version and is **not** reauthorization. It does not
  imply retention-policy compliance, immutable storage, or disaster recovery.

## Promotion gates

1. **DONE (source-safe mock):** request schema and derivation-context propagation;
   synthetic wrap/unwrap/rewrap; wrong scope, unsafe endpoint, redirect and
   redacted-error negative tests.
2. **OPEN:** actual isolated OpenBao instance, correct key configuration and
   ACL-negative tests, rotation, rewrap, restart and backup/restore.
3. **OPEN:** integrate the independently authorized worker with evidence-vault
   manifest/ciphertext and signing provenance; prohibit ordinary agents from
   invoking raw-key unwrapping.
4. **OPEN:** cross-platform host custody, auditing/revocation, failure and
   network-partition drills. Do not claim production KMS.

API reference: https://openbao.org/docs/next/api/secret/transit/
