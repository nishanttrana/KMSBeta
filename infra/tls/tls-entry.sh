#!/bin/sh
# Internal mTLS for an infrastructure daemon (docs/SECURITY/INTERNAL_TLS.md).
#
# Usage: tls-entry.sh <owner> <reload-command> <original entrypoint and args...>
#
# The certs service writes this daemon's Sub CA certificate and key to
# /run/vecta/infra-tls (a subpath of the infra-tls volume) and the internal
# trust bundle to /run/vecta/trust. Daemons that check key ownership can't
# read files owned by the certs user, so this wrapper, still running as root,
# copies them to /etc/vecta-tls owned by <owner> (0600 key), then execs the
# image's own entrypoint. A background loop re-copies renewed files and runs
# <reload-command> so the daemon picks them up without a restart.
set -eu
owner="$1"
reload="$2"
shift 2
src=/run/vecta/infra-tls
trust=/run/vecta/trust
dst=/etc/vecta-tls

i=0
until [ -s "$src/tls.crt" ] && [ -s "$src/tls.key" ] && [ -s "$trust/internal-chain.crt" ] && [ -s "$trust/internal-ca.crt" ]; do
  i=$((i + 1))
  if [ "$i" -gt 300 ]; then
    echo "tls-entry: TLS files not available after 300s" >&2
    exit 1
  fi
  sleep 1
done

install_files() {
  mkdir -p "$dst"
  cp "$src/tls.crt" "$dst/tls.crt.new"
  cp "$src/tls.key" "$dst/tls.key.new"
  cp "$trust/internal-chain.crt" "$dst/internal-chain.crt.new"
  cp "$trust/internal-ca.crt" "$dst/internal-ca.crt.new"
  chown "$owner" "$dst" "$dst"/*.new
  chmod 0700 "$dst"
  chmod 0600 "$dst/tls.key.new"
  chmod 0644 "$dst/tls.crt.new" "$dst/internal-chain.crt.new" "$dst/internal-ca.crt.new"
  for f in tls.crt tls.key internal-chain.crt internal-ca.crt; do
    mv "$dst/$f.new" "$dst/$f"
  done
}
fingerprint() { cat "$src/tls.crt" "$src/tls.key" "$trust/internal-chain.crt" 2>/dev/null | cksum; }

install_files
(
  last=$(fingerprint)
  while sleep 30; do
    now=$(fingerprint)
    if [ -n "$now" ] && [ "$now" != "$last" ]; then
      install_files
      if sh -c "$reload"; then
        echo "tls-entry: reloaded for a renewed certificate"
      else
        echo "tls-entry: reload command failed" >&2
      fi
      last=$now
    fi
  done
) &

exec "$@"
