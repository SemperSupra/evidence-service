#!/usr/bin/env bash
# Disposable, owned-test only. This is a single-node Raft snapshot/restore and restart
# qualification, NOT HA or cross-node disaster recovery.
set -euo pipefail
umask 077
: "${RUNNER_TEMP:?runner scratch path is required}"
image="ghcr.io/openbao/openbao@sha256:d24890f589bc57658a43c18faab2afc4fbedaadad3806d5a638e1adaed2dff8d"
container="evidence-bao-raft-rdte"
volume="evidence-bao-raft-rdte"
scratch="$(mktemp -d "$RUNNER_TEMP/evidence-bao-raft.XXXXXXXX")"
cleanup() {
  docker rm -f "$container" >/dev/null 2>&1 || true
  docker volume rm "$volume" >/dev/null 2>&1 || true
  rm -rf "$scratch"
}
trap cleanup EXIT

cat > "$scratch/openbao.hcl" <<'CONFIG'
api_addr = "http://127.0.0.1:8200"
cluster_addr = "http://127.0.0.1:8201"
storage "raft" {
  path = "/openbao/file"
  node_id = "owned-raft-1"
}
listener "tcp" {
  address = "0.0.0.0:8200"
  tls_disable = true
}
CONFIG
# Configuration contains no secrets; the container's unprivileged user
# must be able to read the bind-mounted file.
chmod 0644 "$scratch/openbao.hcl"

docker volume create "$volume" >/dev/null
# /openbao/file already exists and is owned by the image's unprivileged
# openbao user; Docker copies its ownership when initializing the volume.
start_server() {
  docker run --detach --name "$container" \
    --publish 127.0.0.1:8200:8200 \
    --mount "type=volume,src=$volume,dst=/openbao/file" \
    --mount "type=bind,src=$scratch/openbao.hcl,dst=/etc/openbao/config.hcl,readonly" \
    "$image" server -config=/etc/openbao/config.hcl >/dev/null
  ready=0
  for attempt in $(seq 1 40); do
    if curl --fail --silent --output /dev/null http://127.0.0.1:8200/v1/sys/seal-status; then
      ready=1
      break
    fi
    sleep 1
  done
  if [[ "$ready" != 1 ]]; then
    echo "Persistent OpenBao fixture failed health admission" >&2
    # Pre-initialization diagnostic only: no vault tokens, shares or user data
    # exist at this point. Preserve first error instead of blindly retrying.
    docker inspect --format '{{.State.Status}} {{.State.ExitCode}}' "$container" >&2 || true
    docker logs --tail 35 "$container" >&2 || true
    exit 1
  fi
}
start_server

docker exec -e BAO_ADDR="http://127.0.0.1:8200" "$container" \
  bao operator init -key-shares=1 -key-threshold=1 -format=json > "$scratch/init.json"
unseal="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["unseal_keys_b64"][0])' "$scratch/init.json")"
root_token="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["root_token"])' "$scratch/init.json")"
echo "::add-mask::$unseal"
echo "::add-mask::$root_token"
rm -f "$scratch/init.json"
docker exec -e BAO_ADDR="http://127.0.0.1:8200" "$container" \
  bao operator unseal "$unseal" >/dev/null

docker exec -e BAO_ADDR="http://127.0.0.1:8200" -e BAO_TOKEN="$root_token" "$container" \
  bao secrets enable transit >/dev/null
docker exec -e BAO_ADDR="http://127.0.0.1:8200" -e BAO_TOKEN="$root_token" "$container" \
  bao write transit/keys/evidence-test derived=true convergent_encryption=false exportable=false allow_plaintext_backup=false >/dev/null
cat > "$scratch/restricted.hcl" <<'POLICY'
path "transit/encrypt/evidence-test" { capabilities = ["update"] }
path "transit/decrypt/evidence-test" { capabilities = ["update"] }
path "transit/rewrap/evidence-test" { capabilities = ["update"] }
POLICY
docker cp "$scratch/restricted.hcl" "$container:/tmp/restricted.hcl"
docker exec -e BAO_ADDR="http://127.0.0.1:8200" -e BAO_TOKEN="$root_token" "$container" \
  bao policy write restricted-evidence /tmp/restricted.hcl >/dev/null
scoped_token="$(docker exec -e BAO_ADDR="http://127.0.0.1:8200" -e BAO_TOKEN="$root_token" "$container" \
  bao token create -policy=restricted-evidence -orphan -format=json | \
  python3 -c 'import json,sys; print(json.load(sys.stdin)["auth"]["client_token"])')"
echo "::add-mask::$scoped_token"

OPENBAO_TEST_ADDR=http://127.0.0.1:8200 OPENBAO_TEST_TOKEN="$scoped_token" \
  OPENBAO_PERSIST_PHASE=seal OPENBAO_PERSIST_ROOT="$scratch" \
  go test ./pkg/kmsbundle -run '^TestPersistentOpenBaoRestart$' -count=1 -timeout=90s -v

# The Raft snapshot contains synthetic-but-sensitive key material. It is
# never exposed as an Actions artifact or retained outside this runner.
docker exec -e BAO_ADDR="http://127.0.0.1:8200" -e BAO_TOKEN="$root_token" "$container" \
  bao operator raft snapshot save /tmp/owned-raft.snap >/dev/null
docker cp "$container:/tmp/owned-raft.snap" "$scratch/owned-raft.snap" >/dev/null
chmod 0600 "$scratch/owned-raft.snap"
if [[ ! -s "$scratch/owned-raft.snap" ]]; then
  echo "Synthetic Raft snapshot is empty or absent" >&2
  exit 1
fi
docker exec -e BAO_ADDR="http://127.0.0.1:8200" -e BAO_TOKEN="$root_token" "$container" \
  bao write transit/keys/after-snapshot-only derived=true convergent_encryption=false exportable=false >/dev/null
docker exec -e BAO_ADDR="http://127.0.0.1:8200" -e BAO_TOKEN="$root_token" "$container" \
  bao read transit/keys/after-snapshot-only >/dev/null

# Red-team control: a deliberately truncated private snapshot must not be
# accepted or roll back the live store. No sensitive snapshot contents are
# printed, and the corrupt file is destroyed with the ephemeral container.
if [[ "$(stat -c %s "$scratch/owned-raft.snap")" -le 1024 ]]; then
  echo "Raft snapshot too small for deliberate truncation negative" >&2
  exit 1
fi
dd if="$scratch/owned-raft.snap" of="$scratch/owned-raft-truncated.snap" bs=512 count=1 status=none
chmod 0600 "$scratch/owned-raft-truncated.snap"
docker cp "$scratch/owned-raft-truncated.snap" "$container:/tmp/owned-raft-truncated.snap" >/dev/null
if docker exec -e BAO_ADDR="http://127.0.0.1:8200" -e BAO_TOKEN="$root_token" "$container" \
    bao operator raft snapshot restore /tmp/owned-raft-truncated.snap >/dev/null 2>&1; then
  echo "Invalid Raft snapshot was accepted" >&2
  exit 1
fi
# A rejected snapshot must not destroy the pre-restore synthetic test state.
docker exec -e BAO_ADDR="http://127.0.0.1:8200" -e BAO_TOKEN="$root_token" "$container" \
  bao read transit/keys/after-snapshot-only >/dev/null

docker exec -e BAO_ADDR="http://127.0.0.1:8200" -e BAO_TOKEN="$root_token" "$container" \
  bao operator raft snapshot restore /tmp/owned-raft.snap >/dev/null
# A no-op restore is a failed qualification; the later key must be absent.
if docker exec -e BAO_ADDR="http://127.0.0.1:8200" -e BAO_TOKEN="$root_token" "$container" \
    bao read transit/keys/after-snapshot-only >/dev/null 2>&1; then
  echo "Raft snapshot failed to roll back post-snapshot state" >&2
  exit 1
fi
docker rm -f "$container" >/dev/null
start_server
sealed_status="$(curl --silent --output /dev/null --write-out '%{http_code}' http://127.0.0.1:8200/v1/sys/health)"
if [[ "$sealed_status" != 503 ]]; then
  echo "Restart did not preserve sealed state (HTTP $sealed_status)" >&2
  exit 1
fi
docker exec -e BAO_ADDR="http://127.0.0.1:8200" "$container" \
  bao operator unseal "$unseal" >/dev/null
OPENBAO_TEST_ADDR=http://127.0.0.1:8200 OPENBAO_TEST_TOKEN="$scoped_token" \
  OPENBAO_PERSIST_PHASE=recover OPENBAO_PERSIST_ROOT="$scratch" \
  go test ./pkg/kmsbundle -run '^TestPersistentOpenBaoRestart$' -count=1 -timeout=90s -v
echo "RAFT_SNAPSHOT=ISOLATED_SAME_NODE_ROLLBACK_AND_RESTART_PASS; CROSS_NODE_DISASTER_RECOVERY=NOT_QUALIFIED; HA=NOT_QUALIFIED"
