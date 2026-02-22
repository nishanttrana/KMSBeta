#!/usr/bin/env bash
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

sudo apt-get update
sudo apt-get upgrade -y
sudo apt-get install -y \
  apt-transport-https \
  ca-certificates \
  curl \
  gpg \
  lsb-release \
  jq \
  unzip \
  python3 \
  python3-pip \
  python3-yaml \
  nftables \
  cryptsetup \
  shamir \
  systemd-timesyncd

sudo mkdir -p /opt/vecta /etc/vecta /var/log/vecta /var/lib/vecta
sudo chown -R "${USER}:${USER}" /opt/vecta
