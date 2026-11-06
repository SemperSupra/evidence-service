# Isolated OpenBao worker-token revocation qualification

This workcell adds `TestLiveOpenBaoWorkerRevocation` as the **last** step
of the existing, source-safe, publicly hosted OpenBao dev test. The runner
generates a fresh synthetic restricted worker token and verifies a random
test-data DEK can be wrapped and recovered under its session scope. The
worker then revokes its **own** token through the real OpenBao API and must
fail both subsequent unwrap and wrap operations. Errors may not reveal the
token or ciphertext.

This tests the real authorization-control behavior of a disposable
local OpenBao instance. It does **not** qualify production token lifecycle,
audit-log custody, external identity, eventual revocation across distributed
caches, key retirement, immutable evidence, persistent backup/restore or
three-audience application-layer authorization. The test never revokes a
production identity or exposes keys to humans or agents.

Revoke-self intentionally runs after all other Transit and KMS-bundle
operations because its scoped token is no longer valid. See
[Evidence Service DLE #1](https://github.com/SemperSupra/evidence-service/issues/1).
