FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

# No sudo: uploading a PKCS#11 library and running the helper scripts needs
# no privilege (docs/SECURITY/HSM_INTEGRATION.md). The SSH user owns only the
# provider workspace.
RUN apt-get update \
  && apt-get install -y --no-install-recommends \
    bash \
    ca-certificates \
    coreutils \
    less \
    net-tools \
    opensc \
    openssh-server \
    procps \
    tar \
    unzip \
    zip \
  && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /var/run/sshd /opt/vecta/hsm/scripts /var/lib/vecta/hsm/providers /etc/ssh/authorized_keys

COPY services/hsm-integration/entrypoint.sh /usr/local/bin/hsm-integration-entrypoint
COPY services/hsm-integration/scripts/ /opt/vecta/hsm/scripts/

RUN chmod 0755 /usr/local/bin/hsm-integration-entrypoint \
  && chmod 0755 /opt/vecta/hsm/scripts/*.sh

EXPOSE 22

# sshd starts as root to authenticate and switch to the SSH user; nothing
# else runs as root, and root login is refused.
ENTRYPOINT ["/usr/local/bin/hsm-integration-entrypoint"]
