# Replay-proposal idempotency — shared three-audience source contract

`Controller.RequestReplayOnce` is a nonprivileged **proposal** method that
cannot execute replay, inspect decrypted capture bytes or unwrap session keys.
A human/assistive UI, automation CLI, or MCP agent must pass through the same
trusted identity and scoped grant boundary in `pkg/admission`.

A trusted `OnceQueue` implementation must atomically persist and deduplicate
the idempotency key while binding it to exact authenticated subject, session
and grant. Retries with the same key and tuple must return the **same proposal
ID**; attempts to reuse a key for a different tuple must be denied. The
source-level integration rejects invalid keys, absent or legacy-only queue
implementations, expired/revoked grants and unauthenticated callers. Tests
exercise concurrent requests with a mutex-protected **test double**, proving
the controller's contract but **not** durable persistence or a database
transaction.

There is deliberately no built-in in-memory production backend: an
unaudited memory map would lose idempotency across restart and permit duplicate
work. The next promotion gate is a trusted transactional SQLite/Postgres
queue or other durable store with uniqueness constraints, restart tests,
revocation checks immediately before replay execution, and auditable
human/AT, CLI and MCP integration. The proposal ID is not authorization to
decrypt packets or retrieve raw TLS secrets.

Record qualification and first failures in [DLE #1](https://github.com/SemperSupra/evidence-service/issues/1).
