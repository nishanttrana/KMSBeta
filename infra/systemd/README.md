# Systemd Units

This directory provides appliance systemd units for runtime stack control.

## Primary Units

- `vecta-stack.service`: Starts/stops the selected Docker Compose services based on `/etc/vecta/deployment.yaml`.
- `vecta-deployment.path`: Watches `/etc/vecta/deployment.yaml` and triggers `vecta-stack.service` automatically.
- `vecta-healthcheck.service`: Runs profile-aware health checks.
- `vecta-healthcheck.timer`: Schedules health checks every 5 minutes.
- `vecta-containers.target`: Groups per-container service units.

## Per-container Units

- `container-services.txt` defines all Compose service names.
- `generate-container-units.sh` creates `containers/vecta-<service>.service` for every listed container.

## Install

```bash
bash infra/systemd/install-systemd.sh
```

## Runtime

```bash
sudo systemctl start vecta-stack.service
sudo systemctl status vecta-healthcheck.timer
```
