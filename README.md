# Evidence Service

Standalone, cross-platform **Go evidence and correlation service** for BrowserParity and SupraChat.

**Current qualification stage: synthetic R0 library and inert CLI only.** Public source contains no production capture, TLS interception, key-log enablement, network listener, active export, user credentials or real PCAP data. `evidenced capabilities` reports that privileged operations are unavailable. Do not treat this project as a deployed or authorized monitoring system.

## Source-owned contracts

- `pkg/evidencevault`: restricted **synthetic test-data** artifact store. Original encrypted capture fixture, derived plaintext fixture and TLS key-log fixture have independent random AES-GCM data encryption keys; each DEK is wrapped under a separate externally supplied 32-byte test KEK. The manifest records byte counts and SHA-256 hashes, and is authenticated with a domain-separated HMAC. The KEK must **not** be saved beside the artifacts. This proof is bounded to 32 MiB/artifact, owner-private directories and a single-process test. It is **not** an external KMS, a signed chain of custody or a concurrent/hostile-filesystem-safe production vault.
- `pkg/correlation`: declared transport legs, observations, and bounded join hints. A trace context or timestamp is *not* a verified identity or proof of causality. Multiple application operations can share one TLS/QUIC transport.
- `cmd/evidenced`: inert capability discovery. Production collection and remote APIs are not implemented.

## Test locally

```sh
go test ./... -count=3
go test -race ./...
go vet ./...
go run ./cmd/evidenced capabilities
```

CI runs correlation and inert CLI tests across Linux/Windows/macOS; the **POSIX permission-dependent vault** is exercised only on Linux/macOS and **compile-checked** on Windows. Windows file ACL custody is NOT QUALIFIED (fail closed for deployment). This is a subset of full RDT&E: actual independent kernel PCAP capture, TShark decoding, OpenBao wrapping/recovery, agent/UI grants, TLS 1.3 session-key ingestion and owned tunnel integration remain **not qualified**.

## Security and artifact custody

No production TLS secret capture. RFC 9850 restricts SSLKEYLOGFILE-style secret logging to test-data systems. Decrypted data must be treated as sensitive independently of the key log. Git stores only source, schemas and sanitized receipts. Restricted object storage and an independent managed KMS are planned for sensitive durable evidence; never include secrets, real captures or internal deployment details in public PRs, Actions logs or artifacts. There is no production RBAC or immutable snapshot capability in R0; acceptance must fail closed if those are required.

## Project ownership

- This repository: shared schema, custody/correlation primitives, source-safe tests and eventual service/API.
- `SemperSupra/BrowserParity-private` #76: browser/CDP/BiDi and controlled test-only TLS sensor adapters.
- `SemperSupra/suprachat-private` #2 and public `SemperSupra/suprachat`: owned transport/tunnel integration, existing `TraceNormalizer` and `IEncryptedTracePayloadVault`, accessible UI, CLI and scoped MCP.

Technical decisions, tests and handoff live in this repository's canonical DLE issue; the integration repositories link to it. Avoid opening overlapping issues or leaving accepted PRs unmerged.
