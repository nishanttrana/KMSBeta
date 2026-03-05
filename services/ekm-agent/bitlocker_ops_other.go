//go:build !windows

package main

import "fmt"

// BitLockerStatus represents the state of BitLocker on a volume.
type BitLockerStatus struct {
	MountPoint       string `json:"mount_point"`
	ProtectionStatus string `json:"protection_status"`
	EncryptionMethod string `json:"encryption_method"`
	VolumeStatus     string `json:"volume_status"`
	EncryptionPct    string `json:"encryption_percentage"`
	LockStatus       string `json:"lock_status"`
}

var errUnsupportedOS = fmt.Errorf("bitlocker operations require Windows")

func GetBitLockerStatus(_ string) (BitLockerStatus, error)    { return BitLockerStatus{}, errUnsupportedOS }
func EnableBitLocker(_, _ string) (string, error)              { return "", errUnsupportedOS }
func DisableBitLocker(_ string) error                          { return errUnsupportedOS }
func SuspendBitLocker(_ string) error                          { return errUnsupportedOS }
func ResumeBitLocker(_ string) error                           { return errUnsupportedOS }
func RotateRecoveryPassword(_ string) (string, error)          { return "", errUnsupportedOS }
func GetTPMStatus() (bool, bool, error)                        { return false, false, errUnsupportedOS }
