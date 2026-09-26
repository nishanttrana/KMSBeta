#!/bin/sh
# Runs from /docker-entrypoint.d before nginx starts: wait for the TLS files
# the certs service writes, then reload nginx whenever they are renewed.
set -eu
d=/run/vecta/dashboard-tls
t=/run/vecta/trust/internal-chain.crt
i=0
until [ -s "$d/tls.crt" ] && [ -r "$d/tls.key" ] && [ -s "$t" ]; do
  i=$((i + 1))
  [ "$i" -gt 180 ] && { echo "tls-watch: TLS files not available after 180s" >&2; exit 1; }
  sleep 1
done
(
  last=$(cksum "$d/tls.crt" "$t")
  while sleep 30; do
    now=$(cksum "$d/tls.crt" "$t" 2>/dev/null || true)
    if [ -n "$now" ] && [ "$now" != "$last" ]; then
      nginx -s reload && echo "tls-watch: reloaded nginx for a renewed certificate"
      last=$now
    fi
  done
) &
