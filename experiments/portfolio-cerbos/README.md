# Cerbos 0.57.0 source-safe native RED/BLUE treatment

**Authoritative workset:** [portfolio-access #225](https://github.com/SemperSupra/engineering-governance-private/issues/225). This is not a new authorization service or production policy. It is separate from Casbin native smoke PR #29, source-fit PR #27 and neutral corpus PR #28.

## Security hypothesis

Cerbos documentation for resource policies explicitly states that if a principal has multiple roles and one role allows an action, that role's allow can win, even when another role denies the action. Within a **single** role's matching rules, denial precedes allow. This nuance can violate an assumed global-deny rule if operators model a `suspended` role naively.

Source: https://docs.cerbos.dev/cerbos/latest/policies/resource_policies.html

## R0 independent treatments

**RED — naive/:** Policy has `reader` allow on read and `suspended` deny on read. Expected *documented* native behavior: multi-role `[reader, suspended]` principal reads successfully. That is an explicit security-fit gap, **not** an acceptance of the behavior as safe.

**BLUE — hardened/:** Policy enforces exact shelf attribute match for reader allow and a wildcard-role deny when `principal.attr.suspended == true`. Expected outcome: mixed-role suspended reader denied on shelf A and B, non-suspended reader permitted A but not B, write always denied. Same engine/source; only policy file changes. Treat native compile/test failure as a falsifying result and preserve first failure.

## Environment

Read-only, public-source synthetic GitHub Actions on `ubuntu-24.04`, no OIDC token issuance, no GitHub App permissions, no actual services or credentials. Pull exact tagged `ghcr.io/cerbos/cerbos:0.57.0`; print resolved OCI image digest to the log. Run both native `compile` suites with `strictEvaluation: true`, isolated from the network and mounted policies read-only. **This is R0 discovery; freeze digest and verify signed upstream release before security promotion.**

The tests do not validate trusted human/workload identity, policy distribution/signature, stale-policy fail-closed, secret custody, key lifecycle, audit, accessibility, MCP, or project-native effect admission. They are not comparable to Casbin's in-process performance benchmark because Cerbos is normally a separate PDP. No production candidate gets a weighted score from these tests alone.

Next: review RED/BLUE evidence, prove policy-only diff with real Cerbos resource policy revisions, run the neutral 25-case oracle with an independent adapter, and benchmark full deployed stack under common loads and fixed 30/25/20/15/10 weights.
