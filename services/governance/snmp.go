package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gosnmp/gosnmp"
)

const (
	defaultSNMPTrapOID      = ".1.3.6.1.4.1.53864.1.0.1"
	defaultSNMPRawPayloadKB = 12 * 1024
	defaultSNMPChunkSize    = 900
)

type SNMPPublisher interface {
	PublishSnapshot(ctx context.Context, target string, snapshot map[string]interface{}) error
	ProbeTarget(ctx context.Context, target string) error
}

type noopSNMPPublisher struct{}

func (noopSNMPPublisher) PublishSnapshot(_ context.Context, _ string, _ map[string]interface{}) error {
	return nil
}

func (noopSNMPPublisher) ProbeTarget(_ context.Context, _ string) error {
	return nil
}

type GoSNMPPublisher struct {
	baseOID string
}

func NewGoSNMPPublisher() *GoSNMPPublisher {
	return &GoSNMPPublisher{baseOID: ".1.3.6.1.4.1.53864.1.1"}
}

func (p *GoSNMPPublisher) PublishSnapshot(ctx context.Context, target string, snapshot map[string]interface{}) error {
	cfg, err := parseSNMPTarget(target)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(snapshot)
	if err != nil {
		return err
	}
	if len(raw) > defaultSNMPRawPayloadKB {
		return fmt.Errorf("snmp payload too large: %d bytes (max %d)", len(raw), defaultSNMPRawPayloadKB)
	}
	compressed, err := gzipAndBase64(raw)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(raw)
	hash := hex.EncodeToString(sum[:])
	client, err := cfg.newClient(ctx)
	if err != nil {
		return err
	}
	defer client.Conn.Close() //nolint:errcheck

	ts := time.Now().UTC().Format(time.RFC3339Nano)
	tenantID := strings.TrimSpace(fmt.Sprintf("%v", snapshot["tenant_id"]))
	eventName := strings.TrimSpace(fmt.Sprintf("%v", snapshot["event"]))
	if eventName == "" {
		eventName = "snapshot"
	}
	chunks := chunkString(compressed, defaultSNMPChunkSize)
	if len(chunks) == 0 {
		chunks = []string{""}
	}

	for i, chunk := range chunks {
		vars := []gosnmp.SnmpPDU{
			{Name: ".1.3.6.1.6.3.1.1.4.1.0", Type: gosnmp.ObjectIdentifier, Value: cfg.TrapOID},
			{Name: p.oid("1.0"), Type: gosnmp.OctetString, Value: tenantID},
			{Name: p.oid("2.0"), Type: gosnmp.OctetString, Value: eventName},
			{Name: p.oid("3.0"), Type: gosnmp.OctetString, Value: ts},
			{Name: p.oid("4.0"), Type: gosnmp.Integer, Value: len(chunks)},
			{Name: p.oid("5.0"), Type: gosnmp.Integer, Value: i + 1},
			{Name: p.oid("6.0"), Type: gosnmp.OctetString, Value: hash},
			{Name: p.oid("7.0"), Type: gosnmp.OctetString, Value: chunk},
		}
		if _, err := client.SendTrap(gosnmp.SnmpTrap{
			Variables:  vars,
			IsInform:   false,
			Enterprise: strings.TrimPrefix(cfg.TrapOID, "."),
		}); err != nil {
			return fmt.Errorf("snmp trap send failed on chunk %d/%d: %w", i+1, len(chunks), err)
		}
	}
	return nil
}

func (p *GoSNMPPublisher) ProbeTarget(ctx context.Context, target string) error {
	cfg, err := parseSNMPTarget(target)
	if err != nil {
		return err
	}
	client, err := cfg.newClient(ctx)
	if err != nil {
		return err
	}
	defer client.Conn.Close() //nolint:errcheck
	return nil
}

func (p *GoSNMPPublisher) oid(suffix string) string {
	return strings.TrimSuffix(p.baseOID, ".") + "." + strings.TrimPrefix(strings.TrimSpace(suffix), ".")
}

type snmpTargetConfig struct {
	Transport  string
	Host       string
	Port       uint16
	Version    gosnmp.SnmpVersion
	Community  string
	TrapOID    string
	Timeout    time.Duration
	Retries    int
	SecModel   gosnmp.SnmpV3SecurityModel
	MsgFlags   gosnmp.SnmpV3MsgFlags
	SecParams  *gosnmp.UsmSecurityParameters
	ServerName string
}

func parseSNMPTarget(raw string) (snmpTargetConfig, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return snmpTargetConfig{}, errors.New("snmp target is empty")
	}
	if !strings.Contains(raw, "://") {
		raw = "udp://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return snmpTargetConfig{}, fmt.Errorf("invalid snmp target url: %w", err)
	}
	host := strings.TrimSpace(u.Hostname())
	if host == "" {
		return snmpTargetConfig{}, errors.New("snmp target host is required")
	}
	if ip := net.ParseIP(host); ip == nil {
		if len(host) > 255 {
			return snmpTargetConfig{}, errors.New("snmp target host is invalid")
		}
	}
	port := uint16(162)
	if p := strings.TrimSpace(u.Port()); p != "" {
		num, convErr := strconv.Atoi(p)
		if convErr != nil || num < 1 || num > 65535 {
			return snmpTargetConfig{}, errors.New("snmp target port is invalid")
		}
		port = uint16(num)
	}
	q := u.Query()
	timeoutSec := parsePositiveInt(defaultString(q.Get("timeout_sec"), os.Getenv("GOVERNANCE_SNMP_TIMEOUT_SEC")), 3)
	retries := parsePositiveInt(defaultString(q.Get("retries"), os.Getenv("GOVERNANCE_SNMP_RETRIES")), 1)
	trapOID := normalizeTrapOID(defaultString(q.Get("trap_oid"), defaultSNMPTrapOID))
	versionRaw := strings.ToLower(strings.TrimSpace(defaultString(q.Get("version"), "2c")))
	cfg := snmpTargetConfig{
		Transport: strings.ToLower(strings.TrimSpace(defaultString(u.Scheme, "udp"))),
		Host:      host,
		Port:      port,
		TrapOID:   trapOID,
		Timeout:   time.Duration(timeoutSec) * time.Second,
		Retries:   retries,
	}
	if cfg.Transport == "" {
		cfg.Transport = "udp"
	}
	switch versionRaw {
	case "1", "v1":
		cfg.Version = gosnmp.Version1
		cfg.Community = defaultString(q.Get("community"), defaultString(os.Getenv("GOVERNANCE_SNMP_COMMUNITY"), "public"))
	case "2c", "2", "v2", "v2c":
		cfg.Version = gosnmp.Version2c
		cfg.Community = defaultString(q.Get("community"), defaultString(os.Getenv("GOVERNANCE_SNMP_COMMUNITY"), "public"))
	case "3", "v3":
		cfg.Version = gosnmp.Version3
		secParams, msgFlags, secModel, secErr := parseSNMPv3Security(q)
		if secErr != nil {
			return snmpTargetConfig{}, secErr
		}
		cfg.SecParams = secParams
		cfg.MsgFlags = msgFlags
		cfg.SecModel = secModel
	default:
		return snmpTargetConfig{}, fmt.Errorf("unsupported snmp version: %s", versionRaw)
	}
	return cfg, nil
}

func parseSNMPv3Security(q url.Values) (*gosnmp.UsmSecurityParameters, gosnmp.SnmpV3MsgFlags, gosnmp.SnmpV3SecurityModel, error) {
	user := strings.TrimSpace(defaultString(q.Get("user"), os.Getenv("GOVERNANCE_SNMP_V3_USER")))
	if user == "" {
		return nil, 0, 0, errors.New("snmp v3 requires user")
	}
	authPass := strings.TrimSpace(defaultString(q.Get("auth_pass"), os.Getenv("GOVERNANCE_SNMP_V3_AUTH_PASS")))
	privPass := strings.TrimSpace(defaultString(q.Get("priv_pass"), os.Getenv("GOVERNANCE_SNMP_V3_PRIV_PASS")))
	authProtoRaw := strings.ToLower(strings.TrimSpace(defaultString(q.Get("auth_proto"), defaultString(os.Getenv("GOVERNANCE_SNMP_V3_AUTH_PROTO"), "sha"))))
	privProtoRaw := strings.ToLower(strings.TrimSpace(defaultString(q.Get("priv_proto"), defaultString(os.Getenv("GOVERNANCE_SNMP_V3_PRIV_PROTO"), "aes"))))
	levelRaw := strings.ToLower(strings.TrimSpace(defaultString(q.Get("security_level"), "")))

	msgFlags := gosnmp.NoAuthNoPriv
	if levelRaw == "" {
		if authPass != "" && privPass != "" {
			msgFlags = gosnmp.AuthPriv
		} else if authPass != "" {
			msgFlags = gosnmp.AuthNoPriv
		}
	} else {
		switch levelRaw {
		case "noauthnopriv", "none":
			msgFlags = gosnmp.NoAuthNoPriv
		case "authnopriv":
			msgFlags = gosnmp.AuthNoPriv
		case "authpriv":
			msgFlags = gosnmp.AuthPriv
		default:
			return nil, 0, 0, fmt.Errorf("invalid snmp v3 security_level: %s", levelRaw)
		}
	}

	params := &gosnmp.UsmSecurityParameters{UserName: user}
	if msgFlags == gosnmp.AuthNoPriv || msgFlags == gosnmp.AuthPriv {
		if authPass == "" {
			return nil, 0, 0, errors.New("snmp v3 auth_pass is required")
		}
		params.AuthenticationPassphrase = authPass
		switch authProtoRaw {
		case "md5":
			params.AuthenticationProtocol = gosnmp.MD5
		case "sha", "sha1":
			params.AuthenticationProtocol = gosnmp.SHA
		case "sha224":
			params.AuthenticationProtocol = gosnmp.SHA224
		case "sha256":
			params.AuthenticationProtocol = gosnmp.SHA256
		case "sha384":
			params.AuthenticationProtocol = gosnmp.SHA384
		case "sha512":
			params.AuthenticationProtocol = gosnmp.SHA512
		default:
			return nil, 0, 0, fmt.Errorf("invalid snmp v3 auth_proto: %s", authProtoRaw)
		}
	}
	if msgFlags == gosnmp.AuthPriv {
		if privPass == "" {
			return nil, 0, 0, errors.New("snmp v3 priv_pass is required for authPriv")
		}
		params.PrivacyPassphrase = privPass
		switch privProtoRaw {
		case "des":
			params.PrivacyProtocol = gosnmp.DES
		case "aes", "aes128":
			params.PrivacyProtocol = gosnmp.AES
		case "aes192":
			params.PrivacyProtocol = gosnmp.AES192
		case "aes192c":
			params.PrivacyProtocol = gosnmp.AES192C
		case "aes256":
			params.PrivacyProtocol = gosnmp.AES256
		case "aes256c":
			params.PrivacyProtocol = gosnmp.AES256C
		default:
			return nil, 0, 0, fmt.Errorf("invalid snmp v3 priv_proto: %s", privProtoRaw)
		}
	}
	return params, msgFlags, gosnmp.UserSecurityModel, nil
}

func (c snmpTargetConfig) newClient(ctx context.Context) (*gosnmp.GoSNMP, error) {
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	if dl, ok := ctx.Deadline(); ok {
		remaining := time.Until(dl)
		if remaining > 0 && remaining < timeout {
			timeout = remaining
		}
	}
	client := &gosnmp.GoSNMP{
		Target:    c.Host,
		Port:      c.Port,
		Transport: c.Transport,
		Version:   c.Version,
		Community: c.Community,
		Timeout:   timeout,
		Retries:   c.Retries,
	}
	if c.Version == gosnmp.Version3 {
		client.SecurityModel = c.SecModel
		client.MsgFlags = c.MsgFlags
		client.SecurityParameters = c.SecParams
	}
	if err := client.Connect(); err != nil {
		return nil, fmt.Errorf("snmp connect failed: %w", err)
	}
	return client, nil
}

func normalizeTrapOID(in string) string {
	in = strings.TrimSpace(in)
	if in == "" {
		return defaultSNMPTrapOID
	}
	if !strings.HasPrefix(in, ".") {
		in = "." + in
	}
	return in
}

func gzipAndBase64(raw []byte) (string, error) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(raw); err != nil {
		return "", err
	}
	if err := zw.Close(); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}

func chunkString(in string, size int) []string {
	if size <= 0 {
		size = defaultSNMPChunkSize
	}
	if in == "" {
		return []string{""}
	}
	out := make([]string, 0, (len(in)/size)+1)
	for len(in) > size {
		out = append(out, in[:size])
		in = in[size:]
	}
	out = append(out, in)
	return out
}

func parsePositiveInt(raw string, fallback int) int {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fallback
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n <= 0 {
		return fallback
	}
	return n
}

func defaultString(value string, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return strings.TrimSpace(fallback)
	}
	return value
}
