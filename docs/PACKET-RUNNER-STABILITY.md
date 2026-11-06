# Packet dependency runner stability (2026-11-06)

An accepted `main` [run 42260867970](https://github.com/SemperSupra/evidence-service/actions/runs/42260867970) exposed a **CI venue failure**: an `ubuntu-latest` runner resolved to Ubuntu 26.04.1, the initial `apt-get install` hit its 240-second limit, the index refresh was attempted, then the second `apt-get install` also hit the 240-second limit (exit 124). The owned kernel TCP/TLS 1.3 test did **not execute**. This does not imply a packet decryption failure.

The corrective workcell pins **only** the packet-capture/TShark qualification job to the stable Ubuntu 24.04 hosted image, leaves Go/race checks on their existing latest OS lanes, and bounds package network, lock and installation attempts with visible provenance and one refresh fallback. It does not substitute reconstructed PCAP, skip the independent no-key negative, or loosen TShark verification.

A green pass after this change qualifies the existing **Linux loopback owned-test capture/decrypt** witness only. It does not qualify an independent physical capture sensor, HTTP/2/QUIC, production TLS secret capture or Windows custody.

**Acceptance:** exact-head public five-job CI including an actual successful packet-capture/TShark job, followed by squash merge, clean PR reconciliation and DLE receipt. Keep the failing first run and correction linked. See [DLE #1](https://github.com/SemperSupra/evidence-service/issues/1).
