# Shared authorization admission — bounded RDT&E

`pkg/admission` is a pure fail-closed policy decision primitive for all three
audiences: humans/assistive UI, automation, and agents/MCP. It exposes no
listener, no login, and no vault operations. One policy engine must be used by
all future clients; do not clone policy logic in separate UI or MCP adapters.

## Trust contract

- `Principal` **must be constructed by a trusted authentication service**,
  never from a body parameter, JavaScript input, user-provided `traceparent`,
  or an agent's claimed role.
- `GrantStore` **must be trusted, scoped, durable and revocation-aware**. A
  grant from an MCP call or an untrusted manifest is not authority. Validate
  immutable subject, session, action, issuer, approval and lease.
- Default deny. No role — including custodian — may request an unknown action.
  Secret recovery is denied to ordinary humans, automation and agents. Only a
  trusted custodian or custodial worker with exact authorization can request it.
- Agents may inspect scoped metadata or **request** replay, but cannot use
  replay to retrieve decrypted content, initiate capture, unseal keys or erase
  evidence. A request for replay is not the execution of replay.
- Denial decisions contain stable reason codes without sensitive material.
  The *actual effect boundary* must independently enforce admission and audit;
  checking once before a long job is insufficient.

## Promotion gates

1. **DONE (pure decision unit tests):** exact-subject/session/action/time checks,
   revocation, disabled approvals, unknown-operation and agent negatives.
2. **OPEN:** verified caller identity, trusted grant issuer/store, authenticated
   source receipts, durable revocation and audit; cross-process behavior.
3. **OPEN:** one API shared by accessible human UI, CLI and MCP, plus end-to-end
   concurrency, replay-request vs replay-execution and cancellation tests.
4. **OPEN:** real endpoint capture and vault-custody controls; key material
   must never be emitted to general agent tools.

These tests are decision-logic evidence only, **not** an operational authorization
or production identity proof.
