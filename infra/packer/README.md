# OVA Packaging Pipeline

This directory contains the Packer pipeline for building a Vecta KMS appliance OVA.
The default image is Ubuntu 24.04 minimal server with baseline hardening plus lightweight cleanup.

## Files

- `kms-appliance.pkr.hcl`: Main Packer template.
- `http/user-data`, `http/meta-data`: Ubuntu 24.04 autoinstall seed.
- `scripts/base.sh`: Base package setup.
- `scripts/install-docker.sh`: Docker Engine + Compose plugin setup.
- `scripts/install-vecta.sh`: Installs this repository into `/opt/vecta`, installs systemd units.
- `scripts/hardening.sh`: Baseline host hardening.
- `lightweight-hardened.pkrvars.hcl`: Optional smaller VM profile for lightweight hardened builds.
- `scripts/export-ova.sh`: Exports VM output to OVA (requires VMware `ovftool`).
- `scripts/build-ova.sh`: One-shot init + build helper.

## Build

```bash
ISO_CHECKSUM="sha256:<ubuntu-24.04-checksum>" bash infra/packer/scripts/build-ova.sh
```

Lightweight hardened build:

```bash
ISO_CHECKSUM="sha256:<ubuntu-24.04-checksum>" \
PACKER_VAR_FILE="infra/packer/lightweight-hardened.pkrvars.hcl" \
bash infra/packer/scripts/build-ova.sh
```

Windows/VirtualBox build (single OVA):

```powershell
powershell -ExecutionPolicy Bypass -File .\infra\packer\scripts\build-ova-virtualbox.ps1 -IsoChecksum none
```

By default, the VirtualBox build script uses this offline ISO:
`C:\Users\NishantRana\Downloads\KMS\ubuntu.iso`

Windows/VirtualBox build with explicit binary paths (optional):

```powershell
powershell -ExecutionPolicy Bypass -File .\infra\packer\scripts\build-ova-virtualbox.ps1 `
  -PackerPath "C:\path\to\packer.exe" `
  -VBoxManagePath "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" `
  -IsoChecksum none
```

Use a different local ISO file:

```powershell
powershell -ExecutionPolicy Bypass -File .\infra\packer\scripts\build-ova-virtualbox.ps1 `
  -IsoPath "D:\isos\ubuntu-24.04.3-live-server-amd64.iso" `
  -IsoChecksum none
```

Windows/VirtualBox lightweight hardened build:

```powershell
powershell -ExecutionPolicy Bypass -File .\infra\packer\scripts\build-ova-virtualbox.ps1 `
  -IsoChecksum none `
  -VarFile infra/packer/lightweight-hardened.pkrvars.hcl
```

## Inputs

Pass build overrides with `-var`, for example:

```bash
packer build \
  -var "iso_checksum=sha256:<ubuntu-24.04-checksum>" \
  -var "source_directory=$(pwd)" \
  -var "output_directory=$(pwd)/infra/packer/output" \
  infra/packer/kms-appliance.pkr.hcl
```

## Output

- VM build artifacts under `infra/packer/output/`.
- OVA exported to `infra/packer/output/<vm-name>-<timestamp>.ova` when `ovftool` is available.
- VirtualBox build writes OVA to `infra/packer/output/<vm-name>-vbox/`.
- Installed appliance units include `vecta-deployment.path`, so writing `/etc/vecta/deployment.yaml` from the first-boot wizard auto-triggers `vecta-stack.service`.
