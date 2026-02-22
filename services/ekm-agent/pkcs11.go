package main

import (
	"os"
	"path/filepath"
	"strings"
)

type PKCS11Health struct {
	Ready  bool
	Reason string
}

func CheckPKCS11Readiness(modulePath string) PKCS11Health {
	p := strings.TrimSpace(modulePath)
	if p == "" {
		return PKCS11Health{
			Ready:  false,
			Reason: "pkcs11_module_path_not_set",
		}
	}
	info, err := os.Stat(p)
	if err != nil {
		return PKCS11Health{
			Ready:  false,
			Reason: "pkcs11_module_not_found",
		}
	}
	if info.IsDir() {
		return PKCS11Health{
			Ready:  false,
			Reason: "pkcs11_module_path_is_directory",
		}
	}
	ext := strings.ToLower(filepath.Ext(p))
	if ext != ".dll" && ext != ".so" && ext != ".dylib" {
		return PKCS11Health{
			Ready:  false,
			Reason: "pkcs11_module_invalid_extension",
		}
	}
	return PKCS11Health{
		Ready:  true,
		Reason: "pkcs11_module_present",
	}
}
