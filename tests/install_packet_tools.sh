#!/usr/bin/env bash
# Source-safe Linux Actions dependency admission for the owned TLS fixture.
# No elevated network capture, live keys or private secrets are used here.
set -euo pipefail

if command -v tcpdump >/dev/null 2>&1 && command -v tshark >/dev/null 2>&1; then
  echo 'PACKET_TOOL_INSTALL=PREINSTALLED'
else
  export DEBIAN_FRONTEND=noninteractive
  # Avoid an unconditional index refresh on each ephemeral runner. This
  # bounded first attempt uses the runner's package index when available.
  if sudo timeout --signal=TERM --kill-after=10s 240s \
      apt-get install -y -qq --no-install-recommends \
      -o DPkg::Lock::Timeout=30 tcpdump tshark; then
    echo 'PACKET_TOOL_INSTALL=RUNNER_INDEX'
  else
    # An outdated runner index can produce 404s or missing packages. Retry
    # once after a bounded refresh. Do not silently skip this qualification.
    echo 'PACKET_TOOL_INSTALL=REFRESH_REQUIRED'
    sudo timeout --signal=TERM --kill-after=10s 120s apt-get update -qq
    sudo timeout --signal=TERM --kill-after=10s 240s \
      apt-get install -y -qq --no-install-recommends \
      -o DPkg::Lock::Timeout=30 tcpdump tshark
    echo 'PACKET_TOOL_INSTALL=REFRESHED_INDEX'
  fi
fi

command -v tcpdump >/dev/null
command -v tshark >/dev/null
# Version receipts contain no TLS keys, capture content or credentials.
tcpdump --version | head -n 1
tshark --version | head -n 1
