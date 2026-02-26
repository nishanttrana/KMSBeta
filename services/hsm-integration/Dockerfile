FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
  && apt-get install -y --no-install-recommends \
    bash \
    ca-certificates \
    coreutils \
    curl \
    iputils-ping \
    jq \
    less \
    net-tools \
    opensc \
    openssh-server \
    procps \
    sudo \
    tar \
    unzip \
    wget \
    zip \
  && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /var/run/sshd /opt/vecta/hsm/scripts /var/lib/vecta/hsm/providers

COPY services/hsm-integration/entrypoint.sh /usr/local/bin/hsm-integration-entrypoint
COPY services/hsm-integration/scripts/ /opt/vecta/hsm/scripts/

RUN chmod 0755 /usr/local/bin/hsm-integration-entrypoint \
  && chmod 0755 /opt/vecta/hsm/scripts/*.sh

EXPOSE 22

ENTRYPOINT ["/usr/local/bin/hsm-integration-entrypoint"]
