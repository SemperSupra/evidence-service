# Portfolio Access R0 — bounded source-fit experiment

**Status:** SOURCE-SAFE FIT/NEGATIVE-SPACE CHARACTERIZATION ONLY. Not a production authorization evaluator, identity provider, credential broker, policy store, or working ShelfMark integration.

**Portfolio workset authority:** [engineering-governance-private #225](https://github.com/SemperSupra/engineering-governance-private/issues/225). **Local source ownership:** [Evidence Service #1](https://github.com/SemperSupra/evidence-service/issues/1). Evidence Service remains an evidence/correlation product and its admission implementation must not be silently promoted into portfolio-wide security authority.

## Question

Can the existing `pkg/admission` pure admission contract serve as a source-independent policy-as-data evaluator for ShelfMark, GitHub Apps, MCP APIs and services **without source changes**?

## Exact behavior checked

Run `go test -v ./experiments/portfolio-access-rdte` on the exact repository revision.

| Test | Observable result | Interpretation |
| --- | --- | --- |
| Existing scoped grant | Same synthetic principal/workset/action allowed; foreign workset denied | Existing evidence-domain workset scope works |
| Policy-only addition of `publication.release.request` | Denied with `ROLE_DENIED` although trusted synthetic grant includes operation | **FIT_GAP:** compiled `roleAllows` operation switch; policy cannot introduce new action |
| Policy-only addition of `shelf-reader` role | Denied with `ROLE_DENIED` although trusted synthetic grant includes allowed metadata action | **FIT_GAP:** compiled role switch |
| Trust/resource/revision contract inspection | Public Principal lacks issuer/audience fields; Grant lacks resource/revision fields | **FIT_GAP:** cannot prove verified identity binding, object-level rights or policy provenance through this API |

Each test that asserts a known gap **passes as a characterization of an unsupported feature**. Green CI here is never a claim that portfolio authorization requirements, GitHub integration, real identity, provider revocation, or effect-boundary admission have passed. A future change to any observed field/operation must trigger an independent requalification rather than automatically turning a gap into production acceptance.

The goal is not to modify or weaken Evidence Service's hard-coded safety ceiling. Its restriction is suitable for the evidence use case. The portfolio access design should use a qualified external/configurable policy evaluator, with verified identity and resource scopes provided by trusted boundaries.

## Owner scoring baseline

Hard security gates H0–H7 are mandatory before scoring. After qualified PASS, weights are: security **30**, policy maintainability **25**, operations **20**, integration **15**, performance/cost **10** (total 100). Scores are 0–5 per dimension and must be evidence backed. Proposed candidates: Casbin, Cerbos, Casdoor/Casbin; Cedar, OPA and OpenFGA/SpiceDB as comparators. OpenBao custody is independently qualified and does not replace the evaluator.

## Next independent workcells

1. Produce a neutral JSON synthetic fixture corpus with the three-audience subject, action, resource, context, and accepted policy revision. Cover default deny, deny override, inheritance, cross-shelf, role inheritance, external issuer/audience, agent self-approval, policy-only changes, expiry/revocation, stale policy, and UNKNOWN key issuance. Mark each assertion as **oracle expected** until real candidate execution.
2. Run fixture adapters for Casbin and Cerbos in disposable public-safe free-tier GitHub Actions; compare actual decisions against the same oracle and negative controls. Do not infer results from candidate documentation.
3. Examine native GitHub OIDC/App token and existing OpenBao RDT&E as an independent credential lane. Use disposable synthetic credentials only.
4. Have ShelfMark librarian owner consume the eventual qualified contract, without granting publication or repository-admin effects.
5. Reconcile exact-head CI, first failure, candidate metrics and review into owner DLE #225 and Evidence Service #1. Do not auto-merge or deploy.

Use approved public-runner capacity only for sanitized source and synthetic tests. No real credentials, private worksets, internal addresses, or live API operations belong in public CI.
