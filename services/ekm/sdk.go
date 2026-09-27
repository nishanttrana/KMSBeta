package main

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io/fs"
	"net/http"
	"strings"
	"time"

	jcaprovider "vecta-kms/services/jca-provider"
)

// GetSDKOverview lists the client SDK Vecta ships: the Java JCA provider,
// with the services it registers (services/jca-provider). Vecta ships no
// PKCS#11 module, and nothing observes SDK sessions or mechanisms, so no
// usage figures are reported.
func (s *Service) GetSDKOverview(ctx context.Context, tenantID string) (SDKOverview, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return SDKOverview{}, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id is required")
	}
	out := SDKOverview{
		RefreshedAt: time.Now().UTC().Format(time.RFC3339Nano),
		Providers: []SDKProviderSummary{{
			ID:           "jca",
			Name:         "Java JCA/JCE Provider",
			ArtifactName: "vecta-jca-sdk-all.zip",
			Version:      "source",
			Status:       "available",
			SizeLabel:    humanizeBytes(estimatedSDKSize("jca", "all")),
			Transport:    "HTTPS (TLS 1.3), bearer token",
			Platforms:    []string{"Java 17+ on OpenJDK builds (Oracle JDK needs an Oracle-signed JCE jar)"},
			Capabilities: []string{"Cipher VectaKeyWrap: wrap and unwrap keys under a Vecta TDE key"},
		}},
		Mechanisms: []SDKMechanismUsage{},
		Clients:    []SDKClient{},
	}
	_ = s.publishAudit(ctx, "audit.ekm.sdk_overview_viewed", tenantID, map[string]interface{}{"providers": len(out.Providers)})
	return out, nil
}

func (s *Service) BuildSDKArtifact(ctx context.Context, tenantID string, provider string, targetOS string) (SDKDownloadArtifact, error) {
	tenantID = strings.TrimSpace(tenantID)
	provider = normalizeSDKProvider(provider)
	targetOS = normalizeSDKTargetOS(targetOS)
	if tenantID == "" {
		return SDKDownloadArtifact{}, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id is required")
	}
	if provider == "" {
		return SDKDownloadArtifact{}, newServiceError(http.StatusBadRequest, "bad_request", "provider is required")
	}
	if targetOS == "" {
		targetOS = defaultSDKTarget(provider)
	}

	payload, filename, err := buildSDKArchive(provider, targetOS)
	if err != nil {
		return SDKDownloadArtifact{}, err
	}
	sum := sha256.Sum256(payload)
	out := SDKDownloadArtifact{
		Provider:    provider,
		TargetOS:    targetOS,
		Filename:    filename,
		ContentType: "application/zip",
		Encoding:    "base64",
		Content:     base64.StdEncoding.EncodeToString(payload),
		SizeBytes:   len(payload),
		SHA256:      hex.EncodeToString(sum[:]),
	}
	_ = s.publishAudit(ctx, "audit.ekm.sdk_downloaded", tenantID, map[string]interface{}{
		"provider":   provider,
		"target_os":  targetOS,
		"filename":   filename,
		"size_bytes": len(payload),
		"sha256":     out.SHA256,
	})
	return out, nil
}

func buildSDKArchive(provider string, targetOS string) ([]byte, string, error) {
	files := sdkFiles(provider, targetOS)
	if len(files) == 0 {
		return nil, "", newServiceError(http.StatusBadRequest, "bad_request", "unsupported sdk provider")
	}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for path, content := range files {
		w, err := zw.Create(path)
		if err != nil {
			return nil, "", err
		}
		if _, err := w.Write([]byte(content)); err != nil {
			return nil, "", err
		}
	}
	if err := zw.Close(); err != nil {
		return nil, "", err
	}
	filename := fmt.Sprintf("vecta-%s-sdk-%s.zip", provider, targetOS)
	return buf.Bytes(), filename, nil
}

func sdkFiles(provider string, targetOS string) map[string]string {
	switch normalizeSDKProvider(provider) {
	case "jca":
		return jcaSDKFiles()
	default:
		return map[string]string{}
	}
}

// jcaSDKFiles is the provider source as built into this binary
// (services/jca-provider, go:embed), under vecta-jca-provider/.
func jcaSDKFiles() map[string]string {
	files := map[string]string{}
	_ = fs.WalkDir(jcaprovider.Source, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		raw, err := jcaprovider.Source.ReadFile(p)
		if err != nil {
			return err
		}
		files["vecta-jca-provider/"+p] = string(raw)
		return nil
	})
	return files
}

func normalizeSDKProvider(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "jca", "jce", "java":
		return "jca"
	default:
		return ""
	}
}

func normalizeSDKTargetOS(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "linux", "linux-amd64", "linux-x64":
		return "linux"
	case "windows", "win", "windows-x64":
		return "windows"
	case "mac", "macos", "darwin":
		return "macos"
	case "all", "":
		return "all"
	default:
		return ""
	}
}

func defaultSDKTarget(provider string) string {
	if normalizeSDKProvider(provider) == "jca" {
		return "all"
	}
	return "linux"
}

func estimatedSDKSize(provider string, targetOS string) int {
	raw, _, err := buildSDKArchive(provider, targetOS)
	if err != nil {
		return 0
	}
	return len(raw)
}

func humanizeBytes(n int) string {
	if n <= 0 {
		return "-"
	}
	if n < 1024 {
		return fmt.Sprintf("%d B", n)
	}
	kb := float64(n) / 1024.0
	if kb < 1024 {
		return fmt.Sprintf("%.0f KB", kb)
	}
	mb := kb / 1024.0
	if mb < 10 {
		return fmt.Sprintf("%.1f MB", mb)
	}
	return fmt.Sprintf("%.0f MB", mb)
}
