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

The public unit suite uses synthetic fixtures and an **in-memory fake**
implementing the same WrapKey/UnwrapKey contract as `transitclient.Client`.
The fake is never a production security backend.

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
- Persistent OpenBao KMS, real end-to-end access approval, independently
  enforced revocation, rotation of stored envelopes, vault backup/restore
  across process/host restart and human/automation/MCP effect-boundary tests
  remain **OPEN**. Existing live OpenBao tests qualify **only** the Transit API
  and synthetic rotation semantics, not this full bundle lifecycle.
- No production TLS session-key logging, live third-party tunnels, sovereign
  environment data or private evidence is admitted in public source or CI.

## Next promotion gate

Wire the same bundle-envelope integration test to a disposable *real* OpenBao
instance with a restricted token; exercise wrap/recover, key rotation, rewrap,
manifest signing and wrong-scope negatives on exact source, then separately
qualify persistent restore and audit. The signing key must remain independent
of Transit and artifact storage. See authoritative
[Evidence Service DLE #1](https://github.com/SemperSupra/evidence-service/issues/1).
