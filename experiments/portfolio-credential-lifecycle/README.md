# Portfolio credential lifecycle — isolated synthetic R1

**Authoritative portfolio workset:** [engineering-governance-private #225](https://github.com/SemperSupra/engineering-governance-private/issues/225). This test-only package does not add a broker service, GitHub App, OAuth client, credential storage, real account integration, or privileged operation to Evidence Service.

This independent workcell exercises a minimal **fake provider** and in-memory contract for bounded client authorization and credential lifecycle. All repository IDs (11, 12), subjects, tokens, approval labels, worksets, and permissions are fictional. The source implements no network calls, secret APIs, or production credential handlers.

## Evidence produced
- Explicit selected repository IDs and permissions are required; empty, cross-installation, unrecognized admin and self-approved requests are denied before a fake provider call.
- A repeated identical workset request returns the same opaque receipt; a changed privilege request sharing the workset is denied, not minted.
- Provider CREATE success with lost response produces UNKNOWN; blind retry does **not** create a duplicate; the fake provider's readback reconciles the outcome.
- Failed revoke preserves UNKNOWN, and reconciliation verifies the credential remains active; the next successful provider-confirmed revoke records REVOKED.
- No synthetic bearer token appears in the returned receipt or serialized receipt.

Run from the root: `go test -v -count=3 ./experiments/portfolio-credential-lifecycle` and `go test -race ./experiments/portfolio-credential-lifecycle`. The ordinary public GitHub Actions `qualify.yml` runs this Go package on Linux/macOS and race; the Windows workflow's selected subset excludes it. **No new secret-bearing job, write token or workflow is needed.**

## Explicit gaps and stop rules

This is a **test double**, not a production implementation. The hardcoded synthetic installation ceiling and fictional independent approval are fixtures, not policy-as-data authority. The sample token is not a real secret. The in-memory ledger does not provide durable concurrency or crash recovery. `UNKNOWN` reconciliation is a fake provider read, not proof that a real third-party API supports it. No real JWT signature/issuer/audience validation, verified approval, live GitHub App token issuance, actual revocation, vault custody, or effect admission has been performed. H1/H3/H5/H6/H7 remain unqualified.

Next: compare these state transitions with provider-native GitHub App/OIDC capabilities, qualify separate real identity/authentication and ledger durability on an admitted trusted disposable runtime, then integrate the selected policy engine only at a separately approved access control product boundary. Do not embed this mock broker into Evidence Service runtime.
