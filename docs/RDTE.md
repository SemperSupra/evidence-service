# RDT&E evidence grades and hold gates

| Gate | Method | R0 acceptance | Remaining |
| --- | --- | --- | --- |
| Source safety | Public-source inspection, no keys/network targets | source only | maintainer release review |
| Go custody | File permissions, authenticated AEAD/HMAC, recovery and negatives | synthetic tests | KMS, external signature, immutable store, 64-bit streaming |
| Correlation | Multi-leg/task join hints with ambiguity and no fabricated authority | synthetic tests | real CDP / MCP / QUIC clocks and reconnects |
| Packet source | Owned Linux loopback TCP TLS 1.3 via real tcpdump packet vantage | PUBLIC-GHA TEST CANDIDATE | review actual run receipts; other platforms and independent NIC still open |
| Decryption | TShark on the exact owned kernel PCAP with key log, positive + no-key negative | PUBLIC-GHA TEST CANDIDATE | receipt and independent review needed; HTTP2/QUIC/rekey remains |
| Service interface | Typed human, automation and agent API with same policy | NOT RUN | accessible UI, CLI, MCP, authorization HIL |
| Cloud CI | Public source-safe tri-OS build and correlation tests, vault tests on Linux/macOS, Linux race detector | workflow configured | completed Actions run; Windows custody ACL NOT QUALIFIED |

**Sequential promotion rule:** no claim of service-ready, network-decrypted or production authorized status until the applicable gate is exercised on exact source, independently reviewed, and recorded in DLE. Source-only and synthetic passes cannot replace a real packet witness.

**Repository hygiene:** one issue for shared workset and phase gates, bounded PRs; do not create separate architecture issues for BrowserParity or SupraChat; merge or close accepted/superseded PRs, record failure provenance, and periodically compare `main`, workflows, PRs and stale branches. Never force-push or delete branches without dependency reconciliation.
