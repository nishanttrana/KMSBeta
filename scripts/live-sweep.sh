#!/usr/bin/env bash
# Sweep the running stack for faults nobody has reported: containers that are
# not healthy, and log lines that repeat. Read-only. Run it after every
# deploy or rebuild and before calling a fix done (CLAUDE.md).
#
#   scripts/live-sweep.sh [minutes]     default 20
#
# Prints, per container, each error-like line seen at least MIN_REPEAT times
# (default 5) with identifiers and credentials stripped. Exits 1 when a
# container is not healthy or a line repeats.
set -u
MINUTES="${1:-20}"
MIN_REPEAT="${MIN_REPEAT:-5}"
PROJECT="${COMPOSE_PROJECT_NAME:-}"
if [ -z "$PROJECT" ]; then
  PROJECT="$(docker compose ls -q 2>/dev/null | head -1)"
fi
[ -n "$PROJECT" ] || { echo "no running compose project found"; exit 2; }

fail=0
# TCP health probes open and close a TLS port without a handshake; that line
# is the probe, not a fault.
PROBE_NOISE='TLS handshake error.*EOF|unexpected eof while reading'
# A tab-indented line continues the line above it: the text of a statement in
# Postgres's slow-query log (whose columns include error_message), or a frame
# of a Go stack trace whose panic line is matched on its own.
CONTINUATION=$'^\t'

for c in $(docker ps -a --filter "label=com.docker.compose.project=$PROJECT" --format '{{.Names}}' | sort); do
  state="$(docker inspect -f '{{.State.Status}}{{if .State.Health}}/{{.State.Health.Status}}{{end}}' "$c" 2>/dev/null)"
  case "$state" in
    running|running/healthy) ;;
    *) echo "NOT HEALTHY  $c  ($state)"; fail=1 ;;
  esac
  lines="$(docker logs --since "${MINUTES}m" "$c" 2>&1 \
    | grep -iE 'error|failed|refus|unavailable|denied|unauthorized|panic|fatal' \
    | grep -vE "$PROBE_NOISE" | grep -v "$CONTINUATION" \
    | sed -E 's/(token|password|secret|key)[=:][^ ]*/\1=<redacted>/g; s#://[^@/ ]*@#://<redacted>@#g; s/[0-9]{4}[-\/][0-9]{2}[-\/][0-9]{2}[T ][0-9:.]+Z?( UTC)?//g; s/\[[0-9]+\]//g; s/[0-9a-f]{8}-[0-9a-f-]{27}/<id>/g; s/[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(:[0-9]+)?/<ip>/g' \
    | cut -c1-200 | sort | uniq -c | sort -rn | awk -v m="$MIN_REPEAT" '$1 >= m' | head -5)"
  if [ -n "$lines" ]; then
    echo "REPEATING    $c (last ${MINUTES}m)"
    echo "$lines"
    fail=1
  fi
done
[ "$fail" -eq 0 ] && echo "live sweep: $PROJECT clean over the last ${MINUTES}m"
exit "$fail"
