# OpenBao restart qualification — source-safe test only

This workcell replaces the earlier disposable **dev-mode** assumption for one
bounded test with a real OpenBao server backed by a Docker named volume and
the OpenBao **file** storage backend. The container is deleted and re-created
while the volume is retained. The exact previously signed bundle, independently
trusted public verification key, and scoped Transit token are reused from a
separate Go process after restarting and unsealing the server.

The runner obtains fresh synthetic one-share unseal and root tokens at
initialization and never uploads them, captures, or the volume. The OpenBao
listener is bound to loopback only with HTTP for this isolated test; external
use requires TLS. The test checks sealed-before-unseal behavior and refuses
mismatched signers after recovery.

**What PASS means:** single-node file-storage state survives an OpenBao
container restart, and an identical signed synthetic three-artifact evidence
bundle can be authenticated and recovered afterward with its original
restricted Transit token.

**What PASS does NOT mean:** production durability, HA, snapshot/backup
restore, cross-machine recovery, trustworthy audit/revocation, unseal key
custody, immutable storage, Windows ACL, or physical independent packet
capture. OpenBao warns that the file backend is not recommended in production
because it lacks transactional semantics and file locking. Future RDT&E
should use integrated Raft storage with isolated snapshots and disaster
recovery exercises. See OpenBao documentation:
https://openbao.org/docs/2.5.x/configuration/storage/filesystem/

Scope and authority: [DLE #1](https://github.com/SemperSupra/evidence-service/issues/1).
