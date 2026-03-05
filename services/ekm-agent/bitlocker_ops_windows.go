//go:build windows

package main

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
)

// BitLockerStatus represents the state of BitLocker on a volume.
type BitLockerStatus struct {
	MountPoint       string `json:"mount_point"`
	ProtectionStatus string `json:"protection_status"`
	EncryptionMethod string `json:"encryption_method"`
	VolumeStatus     string `json:"volume_status"`
	EncryptionPct    string `json:"encryption_percentage"`
	LockStatus       string `json:"lock_status"`
}

func runPS(cmd string) (string, error) {
	out, err := exec.Command("powershell.exe", "-NoProfile", "-Command", cmd).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// GetBitLockerStatus returns the BitLocker state of the given volume.
func GetBitLockerStatus(mountPoint string) (BitLockerStatus, error) {
	cmd := fmt.Sprintf(`Get-BitLockerVolume -MountPoint '%s' | ConvertTo-Json -Compress`, mountPoint)
	out, err := runPS(cmd)
	if err != nil {
		return BitLockerStatus{}, fmt.Errorf("get-bitlockervolume: %w: %s", err, out)
	}
	var raw map[string]interface{}
	if err := json.Unmarshal([]byte(out), &raw); err != nil {
		return BitLockerStatus{}, fmt.Errorf("parse bitlocker json: %w", err)
	}
	return BitLockerStatus{
		MountPoint:       mountPoint,
		ProtectionStatus: fmt.Sprintf("%v", raw["ProtectionStatus"]),
		EncryptionMethod: fmt.Sprintf("%v", raw["EncryptionMethod"]),
		VolumeStatus:     fmt.Sprintf("%v", raw["VolumeStatus"]),
		EncryptionPct:    fmt.Sprintf("%v", raw["EncryptionPercentage"]),
		LockStatus:       fmt.Sprintf("%v", raw["LockStatus"]),
	}, nil
}

// EnableBitLocker enables BitLocker on the given mount point.
func EnableBitLocker(mountPoint string, protectorType string) (string, error) {
	var cmd string
	switch strings.ToLower(strings.TrimSpace(protectorType)) {
	case "tpm":
		cmd = fmt.Sprintf(`Enable-BitLocker -MountPoint '%s' -TpmProtector -EncryptionMethod XtsAes256`, mountPoint)
	case "recovery_password", "":
		cmd = fmt.Sprintf(`Enable-BitLocker -MountPoint '%s' -RecoveryPasswordProtector -EncryptionMethod XtsAes256`, mountPoint)
	case "tpm_and_pin":
		cmd = fmt.Sprintf(`$pin = Read-Host -AsSecureString; Enable-BitLocker -MountPoint '%s' -TpmAndPinProtector -Pin $pin -EncryptionMethod XtsAes256`, mountPoint)
	default:
		return "", fmt.Errorf("unsupported protector type: %s", protectorType)
	}
	out, err := runPS(cmd)
	if err != nil {
		return "", fmt.Errorf("enable-bitlocker: %w: %s", err, out)
	}
	return out, nil
}

// DisableBitLocker disables BitLocker on the given mount point.
func DisableBitLocker(mountPoint string) error {
	cmd := fmt.Sprintf(`Disable-BitLocker -MountPoint '%s' -Confirm:$false`, mountPoint)
	out, err := runPS(cmd)
	if err != nil {
		return fmt.Errorf("disable-bitlocker: %w: %s", err, out)
	}
	return nil
}

// SuspendBitLocker suspends BitLocker protection.
func SuspendBitLocker(mountPoint string) error {
	cmd := fmt.Sprintf(`Suspend-BitLocker -MountPoint '%s' -RebootCount 1`, mountPoint)
	out, err := runPS(cmd)
	if err != nil {
		return fmt.Errorf("suspend-bitlocker: %w: %s", err, out)
	}
	return nil
}

// ResumeBitLocker resumes BitLocker protection.
func ResumeBitLocker(mountPoint string) error {
	cmd := fmt.Sprintf(`Resume-BitLocker -MountPoint '%s'`, mountPoint)
	out, err := runPS(cmd)
	if err != nil {
		return fmt.Errorf("resume-bitlocker: %w: %s", err, out)
	}
	return nil
}

// RotateRecoveryPassword removes old recovery protectors and creates a new one.
func RotateRecoveryPassword(mountPoint string) (string, error) {
	// Remove existing recovery password protectors
	removeCmd := fmt.Sprintf(`
$vol = Get-BitLockerVolume -MountPoint '%s'
$vol.KeyProtector | Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' } | ForEach-Object {
  Remove-BitLockerKeyProtector -MountPoint '%s' -KeyProtectorId $_.KeyProtectorId
}
`, mountPoint, mountPoint)
	if _, err := runPS(removeCmd); err != nil {
		// Not fatal — may have no existing recovery passwords
	}
	// Add new recovery password
	addCmd := fmt.Sprintf(`(Add-BitLockerKeyProtector -MountPoint '%s' -RecoveryPasswordProtector).KeyProtector[-1].RecoveryPassword`, mountPoint)
	out, err := runPS(addCmd)
	if err != nil {
		return "", fmt.Errorf("rotate recovery: %w: %s", err, out)
	}
	return out, nil
}

// GetTPMStatus returns TPM presence and readiness.
func GetTPMStatus() (present bool, ready bool, err error) {
	out, err := runPS(`Get-Tpm | ConvertTo-Json -Compress`)
	if err != nil {
		return false, false, fmt.Errorf("get-tpm: %w: %s", err, out)
	}
	var raw map[string]interface{}
	if err := json.Unmarshal([]byte(out), &raw); err != nil {
		return false, false, fmt.Errorf("parse tpm json: %w", err)
	}
	present, _ = raw["TpmPresent"].(bool)
	ready, _ = raw["TpmReady"].(bool)
	return present, ready, nil
}
