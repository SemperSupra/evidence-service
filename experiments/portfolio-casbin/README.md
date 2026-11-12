# Native Apache Casbin R0 source-safe qualification

**Owner:** [portfolio access RDT&E #225](https://github.com/SemperSupra/engineering-governance-private/issues/225). This is independent of the neutral oracle PR #28 and Evidence Service source-fit PR #27. It is not a production authentication/authorization system and changes no Evidence Service runtime code.

## Native source and reproducibility
Use Casbin Go v3.11.0 (`github.com/casbin/casbin/v3`) with an explicit source dependency in nested `go.mod`, plus `model.conf` and two versioned CSV policies. The public, secrets-free workflow installs an exact Go toolchain, downloads this version from the public module proxy with `GOSUMDB=sum.golang.org`, verifies modules, runs triple-repeated native tests and bounded benchmark, and emits the dependency inventory. **R0 bootstrap does not commit the generated go.sum**; a subsequent qualification rep must capture and freeze the full resolved dependency closure before promotion.

### Security semantics under test
- Native `g(sub, role, domain)` domain-aware role links and role inheritance.
- Resource exactness and cross-shelf denial.
- Default deny for unknown operations.
- Deny precedence when an explicit deny policy is added.
- Policy-only switch between `policy_v0.csv` and `policy_v1.csv`: `dave` receives shelf B read in v1, but `alice` does not gain shelf B rights. No application source change between these decisions.
- Native direct `Enforce` latency is measured as a lower-bound library baseline, **not** end-to-end API latency, login latency, vault throughput or operational cost.

### Explicit NOT_RUN boundaries
Identity verification, OIDC issuer/audience validation, GitHub App installation scoping, approved policy distribution, trusted grant store, revocation, lease expiry, stale-cache handling, crash safety, MCP, accessibility, native ShelfMark effect admission, and production service/host operations. These stay mandatory security gates in the portfolio workset.

## Execute
```sh
cd experiments/portfolio-casbin
go mod tidy
go mod verify
go test -v -count=3 ./...
go test -run '^$' -bench '^BenchmarkNativeReadDecision$' -benchtime=100ms -count=3 ./...
```

No provider keys or private worksets. Public Actions PR job has read-only checkout and does not request OIDC permissions. Do not auto-merge. Compare with Cerbos only after a separate native fixture and independent failure analysis; the current test is a **focused Casbin native smoke**, not a 25-case neutral corpus PASS.
