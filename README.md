# KMSBeta

## Install Entry Points

- `install.sh` (Linux installer)
- `install-macos.sh` (macOS wrapper -> same prompt flow)
- `install-windows.ps1` (Windows wrapper using WSL/Git Bash -> same prompt flow)

## Runtime Documentation

- `RUNTIME_CONTROL_FLOW.md`  
  Current runtime/control-flow map for all services and feature profiles that exist in this repo.

## Notes

- First-boot wizard (`/wizard`) is optional and can remain disabled for normal scripted installs.
- Certificate CRWK bootstrap handling is integrated in installer flow for software root-key mode.
