# Evidence Service

Standalone, cross-platform **Go evidence and correlation service** for BrowserParity and SupraChat.

**Current qualification stage: bounded R0 libraries plus a genuine owned-test Linux loopback TLS 1.3 packet-capture/decryption proof.** This is not an independent network vantage or deployed service. Public source contains no production capture, TLS interception, key-log enablement, network listener, active export, user credentials or real traffic data. `evidenced capabilities` reports that privileged operations are unavailable. Do not treat this project as a deployed or authorized monitoring system.

## Source-owned contracts

- `pkg/evidencevault`: restricted **synthetic test-data** artifact store. Original encrypted capture fixture, derived plaintext fixture and TLS key-log fixture have independent random AES-GCM data encryption keys; each DEK is wrapped under a separate externally supplied 32-byte test KEK. The manifest records byte counts and SHA-256 hashes, and is authenticated with a domain-separated HMAC. The KEK must **not** be saved beside the artifacts. This proof is bounded to 32 MiB/artifact, owner-private directories and a single-process test. On its own this low-level primitive does not require external signature verification; use the attested bundle reader and KMS envelope for the independently verified source-safe path. No production hostile-filesystem custody is claimed.
- `pkg/correlation`: declared transport legs, observations, and bounded join hints. A trace context or timestamp is *not* a verified identity or proof of causality. Multiple application operations can share one TLS/QUIC transport.
- `pkg/attestation`: independent Ed25519 signatures over exact manifest bytes, verified with an out-of-band trusted key; integrated into the synthetic `evidencevault.SealAttested/OpenAttested` path; production signing-key lifecycle is not qualified.
- `pkg/transitclient`: bounded OpenBao Transit client for scoped 32-byte key wrap/unwrap/rewrap; tests cover both mocked HTTP and a real *ephemeral localhost* OpenBao server with restricted token and rotation.
- `pkg/kmsbundle`: synthetic evidence bundle containing separately encrypted original/derived/test-key artifacts, two signed custody bindings and a Transit-wrapped random bundle key. An isolated live OpenBao full-bundle recovery/rotation test passed; persistent backup/restore and hostile-filesystem custody are not qualified.
- `pkg/admission` and `pkg/controller`: shared fail-closed policy and nonprivileged metadata/replay-*proposal* controller for humans/AT, automation and agents. Real identity verification, grant store, durable revocation, audit and serving API remain unimplemented.
- `cmd/evidenced`: inert capability discovery. Production collection and remote APIs are not implemented.

## Test locally

```sh
go test ./... -count=3
go test -race ./...
go vet ./...
go run ./cmd/evidenced capabilities
```

Public CI builds the full Go source on Linux, Windows and macOS, tests all packages on Linux/macOS, tests correlation and inert CLI on Windows, and runs the Linux race detector. The POSIX permission-dependent vault is **compile-checked only** on Windows; Windows ACL custody is NOT QUALIFIED. A separate Linux job proves genuine synthetic loopback TCP/TLS 1.3 PCAP/TShark decryption in both directions and a missing-key negative. Isolated OpenBao token scope, rotation, and signed full-bundle recovery are **qualified only in disposable test mode**. Still **not qualified**: persistent OpenBao restart/backup/restore and audit, independent physical network vantage, HTTP/2/3 multiplexing, TLS key-update tests, operational agent/UI grants, and deployed tunnel correlation.

## Security and artifact custody

No production TLS secret capture. RFC 9850 restricts SSLKEYLOGFILE-style secret logging to test-data systems. Decrypted data must be treated as sensitive independently of the key log. Git stores only source, schemas and sanitized receipts. Restricted object storage and an independent managed KMS are planned for sensitive durable evidence; never include secrets, real captures or internal deployment details in public PRs, Actions logs or artifacts. There is no production RBAC or immutable snapshot capability in R0; acceptance must fail closed if those are required.

## Project ownership

- This repository: shared schema, custody/correlation primitives, source-safe tests and eventual service/API.
- `SemperSupra/BrowserParity-private` #76: browser/CDP/BiDi and controlled test-only TLS sensor adapters.
- `SemperSupra/suprachat-private` #2 and public `SemperSupra/suprachat`: owned transport/tunnel integration, existing `TraceNormalizer` and `IEncryptedTracePayloadVault`, accessible UI, CLI and scoped MCP.

Technical decisions, tests and handoff live in this repository's canonical DLE issue; the integration repositories link to it. Avoid opening overlapping issues or leaving accepted PRs unmerged.

## Current RDT&E and housekeeping

The shared status and exact qualification ledger live in [DLE #1](https://github.com/SemperSupra/evidence-service/issues/1). PRs #6–#16 are accepted and squash-merged. PR #16 specifically qualified full signed synthetic bundle recovery against an isolated real OpenBao server under a restricted token, with post-rotation and cross-session substitution negatives. See exact-head public CI and first-failure receipts in DLE #1. Acceptance of isolated primitives does **not** close the durable custody, independent capture or production authorization gates. The repository retains historical first-failure receipts and intentionally distinguishes mocked KMS from a real OpenBao instance.

Reconcile PRs, DLE, exact-source CI and branch refs every batch; never delete unreviewed refs. The GitHub repository currently has `delete_branch_on_merge=false`; enable native automatic deletion of merged branches when authorized, after validating that retained branches have no independent unmerged work. Existing remote branch deletion is not exposed by the connected GitHub interface.
