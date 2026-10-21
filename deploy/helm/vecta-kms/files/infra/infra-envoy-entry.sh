#!/bin/sh
# Envoy entry point (docs/SECURITY/INTERNAL_TLS.md, "External edge key
# exchange"). Runs as PID 1 in the envoy container (dash).
#
# The edge listener's TLS 1.3 key-exchange groups are the root
# administrator's choice in Certificates / PKI > Service mTLS. The certs
# service publishes them as a comma-separated list in
# $TRUST_DIR/edge-ecdh-curves. This script writes that list into the
# listener's ecdh_curves line (the one tagged "vecta:edge-ecdh-curves"),
# starts Envoy, and on a change hot-restarts it (--restart-epoch): the new
# process takes over the listening sockets and the old one drains, so no
# connection is refused. Certs measures the result by handshake.
#
# Fail closed: an invalid list at start stops the container (the restart
# policy retries); an invalid list later keeps the groups in force. Only
# when certs has never published a list does Envoy start with the groups in
# envoy.yaml (PQC preferred).

SRC=${ENVOY_CONFIG:-/etc/envoy/envoy.yaml}
TRUST_DIR=${VECTA_TRUST_DIR:-/run/vecta/trust}
CERT_DIR=${VECTA_RUNTIME_CERT_DIR:-/run/vecta/runtime-certs}
WORK=${ENVOY_WORK_DIR:-/tmp/vecta-envoy}
INTERVAL=${EDGE_POLICY_INTERVAL_S:-15}
CURVES_FILE="$TRUST_DIR/edge-ecdh-curves"
MARK='# vecta:edge-ecdh-curves'

log() { echo "[envoy-entry] $*" >&2; }

# The certificates Envoy serves and presents, and the published groups.
i=0
while [ "$i" -lt 180 ]; do
  if [ -s "$CERT_DIR/envoy/tls.crt" ] && [ -s "$CERT_DIR/envoy/tls.key" ] &&
     [ -s "$CERT_DIR/envoy-client/tls.crt" ] && [ -s "$CERT_DIR/envoy-client/tls.key" ] &&
     [ -s "$TRUST_DIR/internal-ca.crt" ] && [ -s "$CURVES_FILE" ]; then
    break
  fi
  i=$((i + 1))
  sleep 1
done

# curves prints the published list, validated, or fails.
curves() {
  c=$(tr -d ' \r\n' < "$CURVES_FILE") || return 1
  [ -n "$c" ] || { log "$CURVES_FILE is empty"; return 1; }
  for n in $(echo "$c" | tr ',' ' '); do
    case "$n" in
      X25519MLKEM768|X25519|P-256|P-384) ;;
      *) log "$CURVES_FILE names an unsupported group: $n"; return 1 ;;
    esac
  done
  echo "$c"
}

# render writes envoy.yaml with the list $1 (empty: unchanged) to $2.
render() {
  if [ -z "$1" ]; then
    cp "$SRC" "$2"
    return
  fi
  list=$(echo "$1" | sed 's/[^,][^,]*/"&"/g; s/,/, /g')
  sed "s|^\( *\)ecdh_curves: .*$MARK\$|\1ecdh_curves: [$list]  $MARK|" "$SRC" > "$2" || return 1
  [ "$(grep -c "ecdh_curves: \[$list\]  $MARK" "$2")" = "1" ] || { log "no single $MARK line in $SRC"; return 1; }
}

start() {
  /usr/local/bin/envoy -c "$WORK/envoy-$1.yaml" --restart-epoch "$1" \
    --drain-time-s 10 --parent-shutdown-time-s 20 \
    --service-cluster vecta-edge --service-node vecta-edge &
  pid=$!
}

mkdir -p "$WORK" || exit 1
cur=""
if [ -e "$CURVES_FILE" ]; then
  cur=$(curves) || exit 1
else
  log "no published edge groups; starting with those in envoy.yaml"
fi
epoch=0
render "$cur" "$WORK/envoy-0.yaml" || exit 1
start 0
log "edge key exchange: ${cur:-envoy.yaml default} (epoch 0)"

trap 'kill -TERM "$pid" 2>/dev/null; wait "$pid"; exit 0' TERM INT

failed=""
while :; do
  sleep "$INTERVAL" &
  wait $!
  if ! kill -0 "$pid" 2>/dev/null; then
    wait "$pid"
    rc=$?
    log "envoy exited ($rc)"
    exit "$rc"
  fi
  [ -e "$CURVES_FILE" ] || continue
  next=$(curves) || continue
  if [ "$next" = "$cur" ] || [ "$next" = "$failed" ]; then
    continue
  fi
  render "$next" "$WORK/envoy-$((epoch + 1)).yaml" || continue
  old=$pid
  start $((epoch + 1))
  sleep 5
  if kill -0 "$pid" 2>/dev/null; then
    epoch=$((epoch + 1))
    cur=$next
    failed=""
    log "edge key exchange: $cur (hot restart, epoch $epoch)"
  else
    wait "$pid"
    log "envoy rejected the edge groups $next; keeping $cur"
    failed=$next
    pid=$old
  fi
done
