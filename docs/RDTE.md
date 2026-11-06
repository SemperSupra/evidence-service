# RDT&E evidence grades and hold gates

| Gate | Method | R0 acceptance | Remaining |
| --- | --- | --- | --- |
| Source safety | Public-source inspection, no keys/network targets | source only | maintainer release review |
| Go custody | File permissions, authenticated AEAD/HMAC, recovery and negatives | signed bundle + isolated live OpenBao in PRs #11/#15/#16; file-backed restart #18 and same-node Raft snapshot rollback #23 PASS | fresh-node/off-host recovery, HA, immutable storage, hostile-filesystem custody, streaming and Windows ACL |
| Correlation | Multi-leg/task join hints with ambiguity and no fabricated authority | synthetic tests | real CDP / MCP / QUIC clocks and reconnects |
| Packet source | Owned Linux loopback TCP TLS 1.3 via genuine tcpdump loopback packet vantage | PASS: public GHA 42130441758, 15 frames / 6109 bytes | independent physical NIC, other platforms, HTTP/2 and QUIC still open |
| Decryption | TShark on exact owned kernel PCAP with test-data key log, both directions and no-key negative | PASS: public GHA 42130441758 | independent witness, multi-stream HTTP/2, QUIC and key-update tests remain |
| Service interface | One authorization policy across human/AT, automation and agent clients | fail-closed policy/controller and idempotent replay-proposal store/process tests in PRs #8/#12/#19/#20/#24 | trusted identity/grant store, live effect enforcement, accessible UI/CLI/MCP and authorization HIL |
| Cloud CI | Public source-safe tri-OS builds, Linux/macOS Go tests, race detector and owned-test NIC/TShark | PRs #11–#24 exact-head acceptance PASS, including isolated live OpenBao Raft suite in #23 | Windows custody ACL, off-host disaster recovery, production identity/audit and independent vantage remain OPEN |

**Sequential promotion rule:** no claim of service-ready, network-decrypted or production authorized status until the applicable gate is exercised on exact source, independently reviewed, and recorded in DLE. Source-only and synthetic passes cannot replace a real packet witness.

**Repository hygiene:** one issue for shared workset and phase gates, bounded PRs; do not create separate architecture issues for BrowserParity or SupraChat; merge or close accepted/superseded PRs, record failure provenance, and periodically compare `main`, workflows, PRs and stale branches. Never force-push or delete branches without dependency reconciliation.

## Owned NIC test first-failure history

Public CI runs `42128458604` and `42128843007` demonstrated the synthetic
endpoint, Go contracts and Linux/macOS/Windows jobs, but the real NIC job
failed: tcpdump reported **0 packets captured** despite **30 received by its
filter** on the second run. No real packet recovery/decryption claim is
accepted. The next test-only candidate enables libpcap immediate packet
delivery and a 2-second drain before stopping the capture group. It requires
an exact new public CI run before the packet gate can be checked off.

## Accepted bounded TLS 1.3 PCAP run (2026-11-05 UTC)

At PR #3 exact code head `cb06ddcc1ea261c8f9d6c12ad969e6fccd742eae`, public
GitHub Actions run [42130441758](https://github.com/SemperSupra/evidence-service/actions/runs/42130441758)
completed **5/5 PASS**: Linux/macOS/Windows Go contracts, Linux race detector
and true OS loopback NIC capture/TShark replay.

The owned test-only capture receipt reported `genuine_nic_pcap=true`,
`tshark_authenticated_decryption=true`, 15 frames, 6109 bytes, 5 TLS
test-data key-log records, and `missing_key_negative=true`. Actual synthetic
request/response SHA256 digests matched the endpoint fixture:
`895947f360ef71fd3c7e0c04d35b88f710a7bced4af65a8682a9a4e1749fe929`
and `ce3bbf19cd4c04b660c24f93847cab5ba277c17bba108ee9bf1c06cf28f338e9`.
Original encrypted PCAP SHA256 was
`43d0080cd5f4503350b08e499c05ed36b0b1f3a04af285493131c48a7e17ed7b`.

**First failure history remains material:** early run 42129651221 yielded a
24-byte PCAP despite 30 packets received by filter (capture buffering/flush);
run 42129680929 advanced to TShark but failed opening the PCAP (exit 3),
consistent with privileged ownership or access boundary. The accepted fix
streams root-owned tcpdump output over an inherited FD into an *already-open,
runner-owned, mode 0600* file, validates custody before TShark, and includes
bounded stderr on future decoder failures. Do not silently retry a failing
capture or mark a permission error PASS.

**Limits:** This is genuine **local loopback** kernel packet capture, not an
independent network probe, a production browser, deployed SupraChat/OpenAI or
Cloudflare tunnel, or OpenBao/KMS restore. Only owned synthetic TLS 1.3 test
data was used. PCAP/keylog/cert private key are deleted in the temporary test
directory; CI retains sanitized hash-only receipt. Windows vault permissions,
production key custody, multi-connection decryption and multi-vantage causality
remain unqualified.

## November 6, 2026 source-safe extension receipts

- [PR #6](https://github.com/SemperSupra/evidence-service/pull/6), merge `5ab9804`: independently trusted Ed25519 manifest signature primitive; public Actions [42133859631](https://github.com/SemperSupra/evidence-service/actions/runs/42133859631) 5/5 PASS. The service does not yet write signed manifest receipts as part of its retention transaction.
- [PR #7](https://github.com/SemperSupra/evidence-service/pull/7), merge `eb893bd`: derived-context DEK wrap/unwrap/rewrap OpenBao adapter; public Actions [42152659894](https://github.com/SemperSupra/evidence-service/actions/runs/42152659894) 5/5 PASS. Unit tests use an HTTP mock, not a live OpenBao instance or durable key store.
- [PR #8](https://github.com/SemperSupra/evidence-service/pull/8), merge `5ffcd47`: common fail-closed admission decision primitive; [first CI 42152663498](https://github.com/SemperSupra/evidence-service/actions/runs/42152663498) failed formatting and unused test variables, corrected in-place and [42152972331](https://github.com/SemperSupra/evidence-service/actions/runs/42152972331) passed 5/5. No verified identity, grants database or deployed actuator is claimed.

## Latest accepted custody and CI receipts (2026-11-06)

- [PR #10](https://github.com/SemperSupra/evidence-service/pull/10): disposable OpenBao test with derived Transit key and scoped-token ACL negatives.
- [PR #11](https://github.com/SemperSupra/evidence-service/pull/11): signed synthetic bundle publication and recovery; forged independently re-MACed manifest rejected.
- [PR #12](https://github.com/SemperSupra/evidence-service/pull/12): common metadata/replay-proposal controller; expired and revoked grants yield no effect.
- [PR #13](https://github.com/SemperSupra/evidence-service/pull/13): isolated real Transit rotate/rewrap, old-key recovery, wrong-context and unauthorized rotation negatives. First malformed-selector and formatting failures remain in DLE.
- [PR #14](https://github.com/SemperSupra/evidence-service/pull/14): bounded cache-first packet tool installation; genuine TCP/TShark positive/negative capture acceptance preserved.
- [PR #15](https://github.com/SemperSupra/evidence-service/pull/15): signed synthetic KMS-bound evidence bundle with fake-wrapper negative tests.
- [PR #16](https://github.com/SemperSupra/evidence-service/pull/16): exact head `2b1262e3019430ee01fbdf7df0ae6081d99559a9`, public [five-job source-safe CI 42227284340](https://github.com/SemperSupra/evidence-service/actions/runs/42227284340) **PASS**, [isolated full-bundle OpenBao CI 42227284289](https://github.com/SemperSupra/evidence-service/actions/runs/42227284289) **PASS**. This proves the *test-data full-bundle API path*, not a persistent or operational vault.

## Accepted isolated process and recovery receipts (2026-11-06)

- [PR #18](https://github.com/SemperSupra/evidence-service/pull/18): genuine single-node **file-backed OpenBao restart** and previously signed synthetic bundle recovery across separate Go processes.
- [PRs #19/#20](https://github.com/SemperSupra/evidence-service/pull/20): shared idempotent replay-*proposal* controller and private atomic-link file store. No replay execution or production database.
- [PR #21](https://github.com/SemperSupra/evidence-service/pull/21): disposable worker token revoke-self prevents subsequent Transit key wrapping/recovery; exact-head source-safe five-job matrix succeeded after targeted cancelled-macOS retry.
- [PR #22](https://github.com/SemperSupra/evidence-service/pull/22): Ubuntu 24.04 packet-test venue stabilization, retaining genuine NIC TShark positive/no-key negative. Preserve the earlier apt-install failure receipt.
- [PR #23](https://github.com/SemperSupra/evidence-service/pull/23): exact head `1b306cc3b0ac15b5d741a8f8a422f1b9e65d86e6`, [isolated Raft run 42283748687](https://github.com/SemperSupra/evidence-service/actions/runs/42283748687) and [source-safe five-job 42283748683](https://github.com/SemperSupra/evidence-service/actions/runs/42283748683) **PASS**. Genuine Raft snapshot restore rolled back a post-snapshot key and the signed bundle recovered after container restart. First malformed shell generator [42283491001](https://github.com/SemperSupra/evidence-service/actions/runs/42283491001) preserved; preflight `bash -n` added.
- [PR #24](https://github.com/SemperSupra/evidence-service/pull/24): [five-job 42283508298](https://github.com/SemperSupra/evidence-service/actions/runs/42283508298) **PASS**. Ten separate OS-process idempotent proposals, independent process restart, foreign-actor negative. Power-loss/multi-node durability remain OPEN.

**Housekeeping:** root DLE #1 remains authoritative; closed/accepted PRs are squash-merged and not recreated as overlapping issues. Repo `delete_branch_on_merge=false`. Historical branch refs may remain despite merged content; no automatic pruning or force-push workaround is authorized through this connector. For artifact placement, public Git stores code, tests and sanitized receipts only; encrypted restricted captures and key custody remain outside the public repo.
