# Atomic file-backed replay-proposal store (source-safe RDT&E)

`pkg/proposalstore` is a **nonprivileged** implementation of the existing
`controller.OnceQueue` contract. It never executes replay, decrypts packets,
unwraps keys, or creates an actor grant.

An approved caller must first pass `admission.Engine`. The store requires
a pre-existing private local directory (owner-only permissions) and uses a
SHA-256-derived file path for the idempotency key. Each new proposal is staged
in an owner-only, fsynced temporary file and published using same-filesystem
`os.Link`, which fails rather than overwriting an existing key. Competing
cooperative writers either win once or read the already committed record.
An existing key with a different subject, session or grant **fails closed**.

Reopening the store preserves proposal IDs across process restarts. Tests
exercise 50 concurrent calls across two store objects, restart/reopen,
foreign-session and foreign-principal collision, corrupt/symlinked records,
incorrect directory permissions, cancellation and revoked grants. No network
listener, privileged process, real evidence, or production credential is used.

**Limitations:** this is not yet a production transactional database or a
power-failure durability guarantee. Directory sync is best effort and the
scheme is unsuitable for NFS, Windows ACL qualification, hostile local users,
malicious same-UID processes, multi-node HA, or a filesystem without reliable
hard-link atomicity. It does not implement proposal execution or continuous
revocation checks at execution time. Use an independently qualified SQLite,
PostgreSQL or another proper transactional service when deployment requires
those guarantees. Human/AT, automation and MCP adapters all consume the same
controller and trusted identity/grant issuer; they must not call this store
with user-supplied actor claims.

Authority and remaining promotion gates are in
[Evidence Service DLE #1](https://github.com/SemperSupra/evidence-service/issues/1).
