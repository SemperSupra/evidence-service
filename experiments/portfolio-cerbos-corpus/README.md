# Cerbos 0.57.0 — native 25-case neutral corpus

**Portfolio selection authority:** [engineering-governance-private #225](https://github.com/SemperSupra/engineering-governance-private/issues/225). This is separate from [Cerbos RED/BLUE PR #30](https://github.com/SemperSupra/evidence-service/pull/30) and stacks only on [neutral corpus PR #28](https://github.com/SemperSupra/evidence-service/pull/28). No Evidence Service product/runtime code is changed.

The fixed JSON oracle is converted by Python-stdlib `generate_tests.py` into native Cerbos policy tests. The conversion uses subject-to-role context from `subjects.json`; its expected answers come unchanged from the independent corpus, not from the candidate policy. Cerbos then compiles and executes all 25 tests in a source-safe network-isolated container. A separate script requires the native result suite to enumerate exactly the 25 expected case IDs and to report a passing overall verdict.

Policies `shelf.yaml`, `publication.yaml` and `repository.yaml` are **native Cerbos data**, expressing exact-shelf read/write, bounded release-request, and GitHub librarian/workload request scope. No publication approval or unrestricted repository-administration rule is granted. Principal `suspended` produces an explicit wildcard-role denial that guards against the multi-role precedence hazard observed in PR #30.

**Honest evidence split:** The seven untrusted/expired/revoked/stale/workset-negative inputs are represented by synthetic principals assigned an unmatched \`synthetic_no_grant\` role in the generated test suite. This exercises native Cerbos default denial but does **not** demonstrate cryptographic identity verification or provider revocation. The remaining inputs are role/resource/action tests of native policies; no actual OAuth, policy deployment or real identities are present. Casbin's adapter reaches similar expected verdicts through an explicit mock trust preflight; these are not full-stack security-equivalent measurements.

The runner pins the Cerbos OCI digest observed in R0:
`ghcr.io/cerbos/cerbos@sha256:e5e3b150b3cb0090975605254f255164567d67e233634199fb20972e3eaff300`.
Digest pinning is not an independent signature or upstream provenance audit. Required before promotion: release authenticity verification, real principal admission, dynamic policy distribution, stale policy and revoked token tests, public API/MCP enforcement and native ShelfMark effect admission.

**Execution:** the dedicated public GitHub Actions workflow on PR creation checks the neutral oracle, generates fixture YAML without installing Python packages, tests the pinned container in `--network=none`, and emits sanitized case/digest evidence. No secrets, real API keys, mutable policy releases, private hosted minutes, or live service deployment. Keep this PR draft pending exact-head CI and independent red/blue review. Do not select a production winner based on source-only H2 subsets.
