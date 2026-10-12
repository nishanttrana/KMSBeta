#!/usr/bin/env bash
# Builds and installs the SoftHSM the HSM tests run against (CI, or a Linux
# container; CLAUDE.md: HSM tests use a real PKCS#11 library, never a mock).
#
#   scripts/install-softhsm.sh [prefix]        default /opt/softhsm
#
# Then: export SOFTHSM_LIB=<prefix>/lib/softhsm/libsofthsm2.so
#       export PATH=<prefix>/bin:$PATH
#
# Why not `apt install softhsm2`, and why not the 2.7.0 release: cloud BYOK
# (10.0.0-beta) wraps a key inside the HSM with RSA-OAEP and SHA-256.
# SoftHSM takes OAEP with SHA-1 only, up to and including its 2.7.0 release,
# and answers CKR_ARGUMENTS_BAD to anything else. Configurable OAEP
# parameters were added on its main branch afterwards (SoftHSMv2 #833,
# 2026-06) and are in no release yet. CI installed the Ubuntu package
# (2.6.1), so three HSM tests failed on every push from 10.0.0-beta on.
#
# The source is fetched at the one commit below and the script refuses
# anything else. Move the pin to a release once one contains #833. Needs
# git, cmake, a C++ compiler, make, pkg-config and OpenSSL headers; on
# Debian or Ubuntu it installs them.
set -euo pipefail

COMMIT="9ad87341c94ffdf1364ecf27b715475e0d80b0dd" # SoftHSMv2 main, 2026-10-03
PREFIX="${1:-/opt/softhsm}"
STAMP="$PREFIX/.vecta-softhsm-commit"

# The build has its prefix compiled in (softhsm2-util loads the library from
# there), so a copy moved or restored to another path is built again.
if [ -x "$PREFIX/bin/softhsm2-util" ] && [ "$(cat "$STAMP" 2>/dev/null)" = "$COMMIT $PREFIX" ]; then
  echo "SoftHSM at $COMMIT is already installed in $PREFIX"
  exit 0
fi

SUDO=""
if [ "$(id -u)" != "0" ]; then
  SUDO="sudo"
fi
if command -v apt-get >/dev/null 2>&1; then
  $SUDO apt-get update -qq
  $SUDO apt-get install -y -qq --no-install-recommends git ca-certificates cmake g++ make pkg-config libssl-dev
fi

src="$(mktemp -d)"
trap 'rm -rf "$src"' EXIT
git init -q "$src"
git -C "$src" fetch -q --depth 1 https://github.com/softhsm/SoftHSMv2.git "$COMMIT"
git -C "$src" checkout -q FETCH_HEAD
got="$(git -C "$src" rev-parse HEAD)"
if [ "$got" != "$COMMIT" ]; then
  echo "SoftHSM source is at $got, not the pinned $COMMIT: refusing to build it" >&2
  exit 1
fi

cmake -S "$src" -B "$src/build" -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX="$PREFIX" \
  -DWITH_CRYPTO_BACKEND=openssl -DBUILD_TESTS=OFF >/dev/null
cmake --build "$src/build" -j "$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2)" >/dev/null
# Root is needed only where the prefix is not ours to write (/opt).
INSTALL="$SUDO"
if mkdir -p "$PREFIX" 2>/dev/null && [ -w "$PREFIX" ]; then
  INSTALL=""
fi
$INSTALL cmake --install "$src/build" >/dev/null

if [ ! -x "$PREFIX/bin/softhsm2-util" ] || [ ! -f "$PREFIX/lib/softhsm/libsofthsm2.so" ]; then
  echo "SoftHSM did not install into $PREFIX as expected" >&2
  exit 1
fi
printf '%s\n' "$COMMIT $PREFIX" | $INSTALL tee "$STAMP" >/dev/null
echo "SoftHSM at $COMMIT installed in $PREFIX ($("$PREFIX/bin/softhsm2-util" --version))"
