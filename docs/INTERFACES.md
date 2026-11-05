# Integration contracts — not runtime integrations yet

R0 publishes *non-privileged* Go source contracts. A consuming adapter may wrap
its own approved observation metadata into `correlation.Observation`. Session and
transport-leg labels are not trusted solely because the emitter supplied them.

| Origin | Owning repository | R0 source boundary | Acceptance still required |
| --- | --- | --- | --- |
| Browser CDP/BiDi, net vantage | BrowserParity | `pkg/correlation` | selected-tab grants and genuinely captured PCAP |
| SupraChat owned SSE/WS/stdio | SupraChat | `TrafficTrace.cs`, `OwnedTransportTrace.cs` | actor consent, per-leg epoch and trusted attach |
| OpenAI tunnel client | OpenAI-owned public tunnel client + SupraChat | validated opt-in `traceparent` | source-confirmed trace forwarding; no hosted key access |
| Cloudflare Quick Tunnel | SupraChat synthetic lab | nonce/trace fixture | real encrypted leg, origin events, reconnect handling |

**Join guidance:** equal `session_id`, `transport_leg_id` and a transport-native
`connection_epoch` or `stream_id` may produce `CORRELATED_METADATA_ONLY`. It is
not `VERIFIED`, and it does not imply permission, content authenticity, complete
capture or one-to-one MCP-to-TLS mapping. Future signed collector attestations
are necessary to upgrade evidence confidence.

Three audiences use the same future admission API: humans/AT can authorize
within policy, automation uses preexisting scoped grants, and agents may
request read-only metadata or propose actions without direct key retrieval.
