#!/usr/bin/env bash
# Disposable, owned-test only. This is a single-node file-storage restart
# qualification, NOT HA, snapshot recovery, or a production KMS.
set -euo pipefail
umask 077
: "${RUNNER_TEMP:?runner scratch path is required}"
image="ghcr.io/openbao/openbao@sha256:d24890f589bc57658a43c18faab2afc4fbedaadad3806d5a638e1adaed2dff8d"
container="evidence-bao-restart-rdte"
volume="evidence-bao-restart-rdte"
scratch="$(mktemp -d "$RUNNER_TEMP/evidence-bao-restart.XXXXXXXX")"
cleanup() {
  docker rm -f "$container" >/dev/null 2>&1 || true
  docker volume rm "$volume" >/dev/null 2>&1 || true
  rm -rf "$scratch"
}
trap cleanup EXIT

cat > "$scratch/openbao.hcl" <<'CONFIG'
disable_mlock = true
api_addr = "http://127.0.0.1:8200"
storage "file" {
  path = "/openbao/data"
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
# A fresh Docker volume is owned by root. OpenBao's image intentionally runs
# unprivileged; give only that image user access to its private data volume.
image_uid="$(docker run --rm --entrypoint /bin/sh "$image" -c 'id -u')"
image_gid="$(docker run --rm --entrypoint /bin/sh "$image" -c 'id -g')"
docker run --rm --user 0 --entrypoint /bin/sh \
  --mount "type=volume,src=$volume,dst=/openbao/data" "$image" \
  -c 'chown "$1:$2" /openbao/data && chmod 0700 /openbao/data' \
  _ "$image_uid" "$image_gid"
start_server() {
  docker run --detach --name "$container" \
    --publish 127.0.0.1:8200:8200 \
    --mount "type=volume,src=$volume,dst=/openbao/data" \
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
echo "PERSISTENT_OPENBAO=RESTART_SYNTHETIC_PASS; BACKUP_RESTORE=NOT_QUALIFIED; HA=NOT_QUALIFIED"
