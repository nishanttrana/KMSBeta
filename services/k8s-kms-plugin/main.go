// Command k8s-kms-plugin is the Vecta Kubernetes KMS v2 plugin. It runs on
// each control-plane node beside kube-apiserver, serves the KMS v2 gRPC API
// on a Unix socket (k8s.io/kms), and wraps kube-apiserver's data encryption
// keys with a Vecta AES-256 key through keycore (pkg/kmsplugin), as an API
// client of the KMS. See README.md and docs/KUBERNETES_KMS.md.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"google.golang.org/grpc"
	kmsapi "k8s.io/kms/apis/v2"
	"k8s.io/kms/pkg/service"

	"vecta-kms/pkg/agentauth"
	"vecta-kms/pkg/kmsplugin"
)

// Config is the plugin's file (mode 0600). The API key is read from its own
// file so it never sits in the config or on a command line.
type Config struct {
	Server     string `json:"server"`
	TenantID   string `json:"tenant_id"`
	KeyID      string `json:"key_id"`
	ClientID   string `json:"client_id"`
	APIKeyFile string `json:"api_key_file"`
	CAFile     string `json:"ca_file,omitempty"`
	Socket     string `json:"socket"`
	Timeout    string `json:"timeout,omitempty"`
}

func load(path string) (Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	var c Config
	d := json.NewDecoder(strings.NewReader(string(raw)))
	d.DisallowUnknownFields()
	if err := d.Decode(&c); err != nil {
		return Config{}, fmt.Errorf("%s: %w", path, err)
	}
	if c.Socket == "" {
		c.Socket = "/var/run/vecta-kms/kms.sock"
	}
	if c.Server == "" || c.TenantID == "" || c.KeyID == "" || c.ClientID == "" || c.APIKeyFile == "" {
		return Config{}, errors.New("server, tenant_id, key_id, client_id and api_key_file are required")
	}
	return c, nil
}

func httpClient(caFile string) (*http.Client, error) {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS13}
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("%s holds no certificate", caFile)
		}
		tlsCfg.RootCAs = pool
	}
	return &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: tlsCfg}}, nil
}

func main() {
	configPath := flag.String("config", "/etc/vecta-kms/k8s-kms-plugin.json", "plugin configuration file")
	flag.Parse()
	logger := log.New(os.Stderr, "[vecta-k8s-kms] ", log.LstdFlags|log.LUTC)
	cfg, err := load(*configPath)
	if err != nil {
		logger.Fatalf("configuration: %v", err)
	}
	key, err := os.ReadFile(cfg.APIKeyFile)
	if err != nil {
		logger.Fatalf("api key: %v", err)
	}
	client, err := httpClient(cfg.CAFile)
	if err != nil {
		logger.Fatalf("ca: %v", err)
	}
	server := strings.TrimRight(cfg.Server, "/")
	auth, err := agentauth.New(agentauth.Config{
		APIKey: strings.TrimSpace(string(key)), ClientID: cfg.ClientID, TenantID: cfg.TenantID,
		JWTEndpoint: server + "/svc/auth/auth/client-token", HTTPClient: client,
	})
	if err != nil {
		logger.Fatalf("auth: %v", err)
	}
	svc, err := kmsplugin.New(kmsplugin.Config{Server: server, TenantID: cfg.TenantID, KeyID: cfg.KeyID}, client, auth.ApplyAuth)
	if err != nil {
		logger.Fatalf("plugin: %v", err)
	}
	timeout := 10 * time.Second
	if cfg.Timeout != "" {
		if timeout, err = time.ParseDuration(cfg.Timeout); err != nil {
			logger.Fatalf("timeout: %v", err)
		}
	}
	// Refuse to start without a working key: kube-apiserver would otherwise
	// fail every write while the plugin looked healthy.
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	st, err := svc.Status(ctx)
	cancel()
	if err != nil {
		logger.Fatalf("refusing to start: %v", err)
	}
	logger.Printf("key %s ready (%s, healthz %s)", st.KeyID, st.Version, st.Healthz)

	if err := os.Remove(cfg.Socket); err != nil && !errors.Is(err, os.ErrNotExist) {
		logger.Fatalf("socket: %v", err)
	}
	// The KMS v2 API is local IPC on a Unix socket kube-apiserver dials (a
	// Kubernetes mandate, no network). Only root on the node may connect.
	ln, err := net.Listen("unix", cfg.Socket)
	if err != nil {
		logger.Fatalf("socket: %v", err)
	}
	if err := os.Chmod(cfg.Socket, 0o600); err != nil {
		logger.Fatalf("socket mode: %v", err)
	}
	gs := grpc.NewServer(grpc.ConnectionTimeout(timeout))
	kmsapi.RegisterKeyManagementServiceServer(gs, service.NewGRPCService(cfg.Socket, timeout, svc))
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-stop
		logger.Printf("shutting down")
		gs.GracefulStop()
	}()
	logger.Printf("serving KMS v2 on unix://%s", cfg.Socket)
	if err := gs.Serve(ln); err != nil {
		logger.Fatalf("serve: %v", err)
	}
}
