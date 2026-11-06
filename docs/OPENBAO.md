# OpenBao Transit adapter — bounded RDT&E

The source-safe `pkg/transitclient` adapter calls the existing OpenBao
Transit `encrypt`, `decrypt`, and `rewrap` API for one 32-byte DEK at a
time. It does **not** start OpenBao, provision tokens or keys, manage signing
keys, seal packet evidence, authorize callers, or claim a real-vault recovery
drill. Unit tests use a localhost synthetic HTTP mock. Separate isolated public-runner tests use a **real disposable OpenBao dev server**, freshly generated masked test tokens and a restricted derived key; no production credentials are admitted.

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
2. **DONE (disposable isolated server):** actual OpenBao-derived key,
   scoped-token ACL negatives, rotate/rewrap and old-ciphertext recovery
   (PRs #10/#13). **OPEN:** persistent restart, backup/restore and audit.
3. **DONE (test-only bundle composition):** signed manifest + wrapped bundle
   KEK and full live OpenBao synthetic recovery (PRs #15/#16). **OPEN:** real
   approved worker identity and effect-boundary admission; agents must never
   receive a raw-key retrieval endpoint.
4. **OPEN:** cross-platform host custody, auditing/revocation, failure and
   network-partition drills. Do not claim production KMS.

API reference: https://openbao.org/docs/next/api/secret/transit/
