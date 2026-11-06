# Replay proposals across independent OS processes

This RDT&E workcell exercises the accepted owner-private file-backed
`proposalstore.Store` with **ten simultaneous separate Go test processes**,
rather than ten goroutines or ten instances in one address space. Each process
opens the same owner-private synthetic test directory and requests the same
idempotency key. All ten must receive one identical proposal ID.

After every writer exits, a fresh eleventh process must recover that same ID.
A twelfth process attempts to reuse the key with a foreign principal and must
receive a conflict. The test inspects the directory for exactly one committed
record and no staging leaks.

The test uses only disposable local private files; no real queue, human data,
network packet, session key or agent execution is involved. Source-safe public
CI runs it on Linux and macOS (including under race detection on Linux).
Windows ACL and hard-link tests remain compile-only/unqualified.

**Still unqualified:** abrupt host power loss, malicious same-UID writers,
cross-host/cluster transactions, NFS, crashes between hard-link publication
and directory sync, durable transaction/audit semantics, and replay
*execution* authorization. The test proves process separation and live
deduplication on the exercised CI filesystems, not production HA.

Authority: [Evidence Service DLE #1](https://github.com/SemperSupra/evidence-service/issues/1).
