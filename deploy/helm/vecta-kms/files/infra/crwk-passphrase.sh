#!/bin/sh
# Runs inside a throwaway container with the certs key volume at /data
# (start-kms.sh and start-kms.ps1). Makes sure the passphrase that seals the
# certs root wrapping key (CRWK) exists and is not public
# (docs/SECURITY/SECURE_DEFAULTS.md, docs/SECURITY/SECRET_ROTATION.md):
# - absent: written from CERTS_CRWK_BOOTSTRAP_PASSPHRASE when set (passed to
#   the container by name, never on a command line), otherwise generated as
#   32 random bytes in hex;
# - the retired public default: kept as <file>.previous, so the certs service
#   can re-key the CRWK off it and rewrap every CA signer, and replaced by a
#   generated one.
# Never prints a passphrase; stdout carries only status words.
set -eu
umask 077
path="${CERTS_CRWK_PASSPHRASE_FILE:-/var/lib/vecta/certs/bootstrap.passphrase}"
case "$path" in
  /var/lib/vecta/certs/*) ;;
  *) exit 0 ;; # a host-managed file outside the certs volume
esac
target="/data/${path#/var/lib/vecta/certs/}"
# SHA-256 of passphrases that shipped in this repository; keep in step with
# publicCRWKPassphrases in services/certs/root_key_provider.go.
retired="ea55b5cbaeab810eae255287b38a3ad77660bbafe6063af1717d8fa8c8ec031b"

mkdir -p "$(dirname "$target")"
if [ -s "$target" ] && [ ! -e "$target.previous" ] &&
  [ "$(tr -d '\r\n' < "$target" | sha256sum | cut -d' ' -f1)" = "$retired" ]; then
  mv "$target" "$target.previous"
  echo "crwk-public-default-retired"
fi
if [ ! -s "$target" ]; then
  if [ -n "${CERTS_CRWK_BOOTSTRAP_PASSPHRASE:-}" ]; then
    printf '%s' "$CERTS_CRWK_BOOTSTRAP_PASSPHRASE" > "$target.tmp"
  else
    head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$target.tmp"
  fi
  mv "$target.tmp" "$target"
  echo "crwk-passphrase-written"
fi
for f in "$target" "$target.previous"; do
  [ -e "$f" ] || continue
  chown 100:101 "$f"
  chmod 600 "$f"
done
