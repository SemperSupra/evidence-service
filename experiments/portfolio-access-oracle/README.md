# Portfolio Access R0 — neutral synthetic decision corpus

**Cross-portfolio authority:** [engineering-governance-private #225](https://github.com/SemperSupra/engineering-governance-private/issues/225). **Source-safe Evidence Service experiment only:** [Evidence Service #1](https://github.com/SemperSupra/evidence-service/issues/1). No production authn/authz/credential service is created or modified.

## Execution

```sh
go test -v ./experiments/portfolio-access-oracle
go vet ./experiments/portfolio-access-oracle
```

The test validates JSON schema shape, unique case IDs, principal references, issuer/audience and policy revision fields, positive/negative coverage, and fixed expected verdicts. **It does NOT execute Casbin, Cerbos, Casdoor, Cedar, OPA or any production authorization evaluator.** A green job means CORPUS_SCHEMA=PASS, AUTHZ_ENGINE=NOT_RUN, not an authorization gate PASS.

## Synthetic reference contracts (fixture v0)

Each `scenario` names a deliberately synthetic precondition for a future candidate adapter. An adapter must implement it with the candidate's *native* policy/configuration mechanisms, never with a hardcoded case-ID allowlist. The expected verdict is the independent reference oracle.

- `reader-grant-a`: authenticated `alice` has reader on shelf A; read A allowed, B denied.
- `editor-grant-a`: `bob` has editor on A, inherits reader on A, not B.
- `publisher-grant-a`: `carol` may *request* publication for A, but not approve independently or publish without a separate native effect admission.
- `agent-grant-a`: `agent-1` may request A publication but not self-approve.
- `librarian-org-grant`: `lib-1` may request a new repository for synthetic `org:example`, not administer the whole organization.
- `reader-expired`: previously valid reader grant expired at the evaluation instant.
- `reader-revoked`: previously valid reader grant revoked before evaluation.
- `reader-with-deny`: explicit exact deny on A overrides inherited/other allow.
- `reader-stale`: approved policy revision is newer than the presented revision; fail closed.
- `reader-pre-change`: `dave` has no read B grant under policy-v0.
- `reader-post-change`: the *same subject/action/resource* becomes allowed by policy-v1 without changing candidate application source or rebuilding the application.
- `reader-foreign-workset`: grant bound to a different admitted workset; deny.
- `workload-verified`: synthetic verification adapter has authenticated GitHub-style workload with matching audience and repository binding.
- `workload-untrusted`: issuer shape alone is insufficient; missing matching repository/workflow binding denies.
- All other cases use the named baseline scenario with the negative request mutation described by their `reason` (unverified identity, untrusted issuer, wrong audience, missing operation, etc).

All subjects, repositories, issuers, worksets, grants and policies in this corpus are **fictional test inputs**. The `principal.authenticated` Boolean is test-oracle input, **not** proof that an actual OIDC token was validated. Candidate suites must separately test the trusted authentication boundary.

## Three-audience and operating acceptance

Coverage: 25 cases (8 allow and 17 deny), including humans, automation and agents. Every nontrivial authorization permit still requires project-local effect admission for mutations. Compare candidate behavior using the same JSON corpus, exact version, and a native adapter for each engine. Adapters must report **PASS / FAIL / NOT_RUN / NOT_APPLICABLE** per case, along with dependency versions and execution receipts.

The owner weighted scoring is security 30%, policy maintainability 25%, operational simplicity 20%, integration effort 15%, performance/cost 10%; every security hard gate H0–H7 is mandatory first. Keep policy changes in separate data files, rather than source conditional branches.

## Next engineering workcell

- Implement a source-pinned Casbin test adapter and a separately source-pinned Cerbos adapter against this corpus on disposable public GitHub Actions with no credentials.
- Include negative mutation tests proving the adapter did not simply echo expected verdicts or case IDs.
- Measure policy-only amendment, identity and resource scope correctness, denial precedence, repeated decision latency, memory/CPU, startup/shutdown, and operator steps.
- Report exact first failures and preserve a NONE_QUALIFIED outcome. Cross-project authority remains #225; no auto-merge, production keys, deployments or privilege changes.
