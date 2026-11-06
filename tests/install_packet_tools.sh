#!/usr/bin/env bash
# Source-safe Linux Actions dependency admission for the owned TLS fixture.
# No elevated network capture, live keys or private secrets are used here.
set -euo pipefail

echo "PACKET_TOOL_RUNNER=$(grep '^PRETTY_NAME=' /etc/os-release | cut -d= -f2-)"

if command -v tcpdump >/dev/null 2>&1 && command -v tshark >/dev/null 2>&1; then
  echo 'PACKET_TOOL_INSTALL=PREINSTALLED'
else
  # Avoid an unconditional index refresh on each ephemeral runner. This
  # bounded first attempt uses the runner's package index when available.
  if sudo timeout --signal=TERM --kill-after=10s 150s \
      env DEBIAN_FRONTEND=noninteractive apt-get install -y -q --no-install-recommends \
      -o DPkg::Lock::Timeout=15 -o Acquire::Retries=1 \
      -o Acquire::http::Timeout=20 -o Acquire::https::Timeout=20 tcpdump tshark; then
    echo 'PACKET_TOOL_INSTALL=RUNNER_INDEX'
  else
    # An outdated runner index can produce 404s or missing packages. Retry
    # once after a bounded refresh. Do not silently skip this qualification.
    echo 'PACKET_TOOL_INSTALL=REFRESH_REQUIRED'
    sudo timeout --signal=TERM --kill-after=10s 90s env DEBIAN_FRONTEND=noninteractive apt-get update -q
    sudo timeout --signal=TERM --kill-after=10s 150s \
      env DEBIAN_FRONTEND=noninteractive apt-get install -y -q --no-install-recommends \
      -o DPkg::Lock::Timeout=15 -o Acquire::Retries=1 \
      -o Acquire::http::Timeout=20 -o Acquire::https::Timeout=20 tcpdump tshark
    echo 'PACKET_TOOL_INSTALL=REFRESHED_INDEX'
  fi
fi

command -v tcpdump >/dev/null
command -v tshark >/dev/null
# Version receipts contain no TLS keys, capture content or credentials.
tcpdump --version | sed -n '1p'
tshark --version | sed -n '1p'
