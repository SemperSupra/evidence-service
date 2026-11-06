# KMS-backed signed bundle custody — test-only integration R0

`pkg/kmsbundle` composes the existing source-safe Go primitives without
forking OpenBao, TLS, PCAP, Wireshark or the Evidence Service policy engine.

## Synthetic bundle lifecycle

1. Require an owner-private evidence parent and an independently trusted
   Ed25519 signer. Create a private staging directory on the same filesystem.
2. Generate a **new random 32-byte bundle KEK** in worker memory. Use it to
   encrypt independently keyed synthetic original PCAP, derived content and
   test-data TLS key-log artifacts using `evidencevault.SealAttested`.
3. Bind the bundle KEK to a derived OpenBao Transit scope containing the exact
   session and random bundle IDs. Store **only the Transit-wrapped KEK**.
4. Sign a second envelope over the manifest digest, session/bundle IDs,
   derivation context, wrapping reference and signer identity. Write it with
   owner-only permissions, then publish the complete bundle by rename.
5. A separately authorized analysis worker verifies the envelope signature,
   independently trusted signer, manifest hash and scope **before asking Transit
   to unwrap**. It then calls `evidencevault.OpenAttested` to verify the
   independent manifest receipt and AEAD/HMAC before opening one artifact.
6. The worker zeros temporary key buffers on a best-effort basis; this is **not**
   a secure-memory, crash-safety or memory-forensics guarantee.

The public unit suite uses synthetic fixtures and an **in-memory fake** implementing the same WrapKey/UnwrapKey contract as `transitclient.Client`. In addition, [PR #16](https://github.com/SemperSupra/evidence-service/pull/16) qualified the **complete signed bundle against an isolated real OpenBao dev server**: all three synthetic artifact recoveries, recovery after an authorized Transit rotation, and rejection of a cross-session signed envelope substitution. Neither the fake nor the dev server establishes production durability.

## Threat and qualification boundaries

- A stolen/modified **wrapped-key sidecar**, forged manifest, altered
  derivation scope, wrong signer, wrong verification key, missing file or
  failed wrap must not yield plaintext or publish a partial bundle.
- The independent signature provides protection against manifest forgery by
  an attacker holding only the artifact-wrapping KEK. It does **not** protect
  against compromise of the signing key and does not substitute authorization.
- The wrapper token must be admitted by policy, restricted to the intended
  derived Transit key, audited, and supplied independently of the public
  artifacts; no agent or UI is given a raw key retrieval endpoint.
- Evidence files, including the encrypted original, derived application
  content, restricted test-only key log, wrapped KEK and signatures, stay
  linked by the same signed manifest identities. They are not original network
  packets unless the source capture is genuine.
- File checks are owner-private POSIX test primitives, **not** a hostile
  filesystem openat/TOCTOU proof, Windows ACL custody, immutable storage or
  robust recovery after abrupt process termination. The public Windows CI
  lane only compiles this package, not its POSIX custody test suite.
- **Isolated, ephemeral full-bundle Transit interoperability is accepted.** Persistent OpenBao seal/unseal, backup/restore across process or host restart, rewrapping and re-signing stored envelope records, immutable storage, real end-to-end access approval, independent revocation and human/automation/MCP effect-boundary tests remain **OPEN**.
- No production TLS session-key logging, live third-party tunnels, sovereign
  environment data or private evidence is admitted in public source or CI.

## Next promotion gate

Admit a persistent *isolated* OpenBao backend with retained storage and
restricted test keys; qualify service restart/unseal, backup/restore, deliberate
key rotation, audit trails, and recovery of the exact signed bundle after
restart. Separately qualify immutable storage and authorized effect-boundary
enforcement. The signing key must remain independent of Transit and the
artifact store. See authoritative
[Evidence Service DLE #1](https://github.com/SemperSupra/evidence-service/issues/1).
