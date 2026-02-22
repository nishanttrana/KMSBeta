#!/usr/bin/env bash
set -euo pipefail

sudo sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
sudo sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
sudo systemctl restart ssh

sudo mkdir -p /etc/systemd/system/docker.service.d
cat <<'EOF' | sudo tee /etc/systemd/system/docker.service.d/10-vecta-hardening.conf >/dev/null
[Service]
NoNewPrivileges=true
PrivateTmp=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
EOF

cat <<'EOF' | sudo tee /etc/sysctl.d/99-vecta-hardening.conf >/dev/null
kernel.kptr_restrict=2
kernel.dmesg_restrict=1
kernel.unprivileged_bpf_disabled=1
kernel.unprivileged_userns_clone=0
fs.protected_hardlinks=1
fs.protected_symlinks=1
fs.suid_dumpable=0
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.default.send_redirects=0
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.default.rp_filter=1
net.ipv4.tcp_syncookies=1
net.ipv4.conf.all.log_martians=1
net.ipv4.conf.default.log_martians=1
net.ipv6.conf.all.accept_redirects=0
net.ipv6.conf.default.accept_redirects=0
net.ipv6.conf.all.accept_source_route=0
net.ipv6.conf.default.accept_source_route=0
EOF

for svc in apport.service snapd.service snapd.socket snapd.seeded.service; do
  sudo systemctl disable --now "${svc}" >/dev/null 2>&1 || true
done

if [[ -f /etc/default/apport ]]; then
  echo "enabled=0" | sudo tee /etc/default/apport >/dev/null
fi

sudo apt-get purge -y snapd >/dev/null 2>&1 || true

sudo systemctl daemon-reload
sudo systemctl restart docker
sudo sysctl --system >/dev/null

sudo timedatectl set-ntp true
sudo systemctl enable systemd-timesyncd

sudo apt-get autoremove -y --purge
sudo apt-get clean
sudo rm -rf /var/lib/apt/lists/*
sudo rm -rf /tmp/* /var/tmp/*
sudo find /var/log -type f -name "*.log" -exec truncate -s 0 {} \; || true
