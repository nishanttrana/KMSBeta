package main

import (
	"bufio"
	"bytes"
	stdcrypto "crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Key material in files: the code scan (WORKSPACE_ROOT) and uploads
// (POST /discovery/upload, 7.18.0-beta) share this parser. A finding records
// where it is and a fingerprint, never the secret. Certificates, public keys
// and SSH public keys are inventoried by the key they hold; a private key,
// keystore, cloud access key or long hex string is a secret and the asset is
// "exposed" (assetClass).

type finding struct {
	kind, algorithm, fingerprint, name string
	line                               int
	meta                               map[string]interface{}
}

// secretKinds: findings that are a secret wherever they are found.
var secretKinds = map[string]bool{"private_key_material": true, "cloud_access_key": true, "hex_secret": true, "keystore": true}

var reSSHPublicKey = regexp.MustCompile(`(?:^|\s)(ssh-ed25519|ssh-rsa|ssh-dss|ecdsa-sha2-nistp(?:256|384|521)|sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-nistp256@openssh\.com)\s+(AAAA[0-9A-Za-z+/]+={0,3})(?:\s+(\S.*))?$`)

// keystoreExt: containers of private keys that open only with a password.
var keystoreExt = map[string]bool{".p12": true, ".pfx": true, ".jks": true, ".keystore": true, ".bcfks": true}

func secretFingerprint(secret []byte) string {
	sum := sha256.Sum256(secret)
	return hex.EncodeToString(sum[:6])
}

func sshFingerprint(blob []byte) string {
	sum := sha256.Sum256(blob)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}

// findMaterial parses one file. name is only used to recognise a keystore by
// its extension.
func findMaterial(name string, raw []byte) []finding {
	if keystoreExt[strings.ToLower(filepath.Ext(name))] {
		return []finding{{kind: "keystore", fingerprint: secretFingerprint(raw), meta: map[string]interface{}{"format": strings.TrimPrefix(strings.ToLower(filepath.Ext(name)), ".")}}}
	}
	var out []finding
	line := 0
	sc := bufio.NewScanner(bytes.NewReader(raw))
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line++
		text := sc.Text()
		if m := reSSHPublicKey.FindStringSubmatch(text); m != nil {
			if f, ok := sshPublicKeyFinding(m, text, line); ok {
				out = append(out, f)
				continue
			}
		}
		if m := reAKIA.FindString(text); m != "" {
			out = append(out, finding{kind: "cloud_access_key", fingerprint: secretFingerprint([]byte(m)), line: line})
		} else if m := reHexSecret.FindString(text); m != "" {
			out = append(out, finding{kind: "hex_secret", fingerprint: secretFingerprint([]byte(m)), line: line})
		}
	}
	rest, sawPEM := raw, false
	for {
		before := rest
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		sawPEM = true
		at := len(raw) - len(before) + bytes.Index(before, []byte("-----BEGIN "+block.Type))
		ln := bytes.Count(raw[:max(at, 0)], []byte("\n")) + 1
		if f, ok := pemFinding(block, ln); ok {
			out = append(out, f)
		}
	}
	// A DER certificate (.cer, .der) has no PEM armour.
	if !sawPEM && len(out) == 0 {
		if c, err := x509.ParseCertificate(raw); err == nil {
			out = append(out, certFinding(c, 0))
		}
	}
	return out
}

func sshPublicKeyFinding(m []string, text string, line int) (finding, bool) {
	blob, err := base64.StdEncoding.DecodeString(m[2])
	if err != nil {
		return finding{}, false
	}
	typ, _, ok := sshString(blob)
	if !ok || string(typ) != m[1] {
		return finding{}, false
	}
	// authorized_keys ends with a comment (user@host); known_hosts starts
	// with the hosts.
	name := strings.TrimSpace(m[3])
	if name == "" {
		name = strings.TrimSpace(text[:strings.Index(text, m[1])])
		if f := strings.Fields(name); len(f) > 0 {
			name = f[len(f)-1]
		}
	}
	if len(name) > 120 {
		name = name[:120]
	}
	return finding{kind: "ssh_public_key", algorithm: sshKeyName(blob), fingerprint: sshFingerprint(blob), name: defaultString(name, "SSH public key"), line: line,
		meta: map[string]interface{}{"key_type": m[1]}}, true
}

func pemFinding(block *pem.Block, line int) (finding, bool) {
	switch {
	case block.Type == "CERTIFICATE" || block.Type == "TRUSTED CERTIFICATE":
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return finding{}, false
		}
		return certFinding(c, line), true
	case block.Type == "CERTIFICATE REQUEST" || block.Type == "NEW CERTIFICATE REQUEST":
		r, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil {
			return finding{}, false
		}
		sum := sha256.Sum256(block.Bytes)
		return finding{kind: "certificate_request", algorithm: publicKeyName(r.PublicKey), fingerprint: hex.EncodeToString(sum[:]), name: defaultString(r.Subject.CommonName, "certificate request"), line: line,
			meta: map[string]interface{}{"subject": r.Subject.String(), "signature_algorithm": r.SignatureAlgorithm.String()}}, true
	case block.Type == "PUBLIC KEY":
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return finding{}, false
		}
		return finding{kind: "public_key", algorithm: publicKeyName(pub), fingerprint: secretFingerprint(block.Bytes), name: "public key", line: line}, true
	case block.Type == "RSA PUBLIC KEY":
		pub, err := x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			return finding{}, false
		}
		return finding{kind: "public_key", algorithm: publicKeyName(pub), fingerprint: secretFingerprint(block.Bytes), name: "public key", line: line}, true
	case strings.Contains(block.Type, "PRIVATE KEY"):
		return finding{kind: "private_key_material", algorithm: privateKeyName(block), fingerprint: secretFingerprint(block.Bytes), line: line}, true
	}
	return finding{}, false
}

func certFinding(c *x509.Certificate, line int) finding {
	sum := sha256.Sum256(c.Raw)
	name := c.Subject.CommonName
	if name == "" && len(c.DNSNames) > 0 {
		name = c.DNSNames[0]
	}
	dns := c.DNSNames
	if len(dns) > 10 {
		dns = dns[:10]
	}
	return finding{kind: "certificate", algorithm: publicKeyName(c.PublicKey), fingerprint: hex.EncodeToString(sum[:]), name: defaultString(name, "certificate"), line: line,
		meta: map[string]interface{}{
			"subject": c.Subject.String(), "issuer": c.Issuer.String(), "serial": c.SerialNumber.Text(16),
			"not_before": c.NotBefore.UTC().Format(time.RFC3339), "not_after": c.NotAfter.UTC().Format(time.RFC3339),
			"signature_algorithm": c.SignatureAlgorithm.String(), "is_ca": c.IsCA,
			"self_signed": bytes.Equal(c.RawIssuer, c.RawSubject), "dns_names": dns,
		}}
}

// privateKeyName names a private key by its public half. An OpenSSH key
// carries its public key in the clear even when the private part is
// encrypted, so it is named without a passphrase.
func privateKeyName(block *pem.Block) string {
	if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		if s, ok := k.(interface{ Public() stdcrypto.PublicKey }); ok {
			return publicKeyName(s.Public())
		}
	}
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return publicKeyName(&k.PublicKey)
	}
	if k, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return publicKeyName(&k.PublicKey)
	}
	if block.Type == "OPENSSH PRIVATE KEY" {
		return openSSHPrivateKeyName(block.Bytes)
	}
	return "UNKNOWN" // encrypted PKCS#8 and others: reported, not guessed
}

// openSSHPrivateKeyName reads the first public key of an openssh-key-v1
// container (PROTOCOL.key in the OpenSSH sources).
func openSSHPrivateKeyName(b []byte) string {
	const magic = "openssh-key-v1\x00"
	if !bytes.HasPrefix(b, []byte(magic)) {
		return "UNKNOWN"
	}
	rest := b[len(magic):]
	for i := 0; i < 3; i++ { // ciphername, kdfname, kdfoptions
		var ok bool
		if _, rest, ok = sshString(rest); !ok {
			return "UNKNOWN"
		}
	}
	if len(rest) < 4 {
		return "UNKNOWN"
	}
	pub, _, ok := sshString(rest[4:])
	if !ok {
		return "UNKNOWN"
	}
	return sshKeyName(pub)
}

// materialAssets turns one file's findings into assets for source "code" or
// "upload".
func (s *Service) materialAssets(tenantID, scanID, source, file string, fs []finding) []CryptoAsset {
	out := make([]CryptoAsset, 0, len(fs))
	now := s.now()
	for _, f := range fs {
		loc := file
		if f.line > 0 {
			loc = fmt.Sprintf("%s:%d", file, f.line)
		}
		md := map[string]interface{}{"file": file, "line": f.line}
		for k, v := range f.meta {
			md[k] = v
		}
		a := CryptoAsset{
			ID: assetDeterministicID(tenantID, source, f.kind, file, fmt.Sprint(f.line), f.fingerprint), TenantID: tenantID, ScanID: scanID,
			AssetType: f.kind, Name: defaultString(f.name, filepath.Base(file)), Location: loc, Source: source,
			Algorithm: f.algorithm, StrengthBits: strengthBits(f.algorithm), Status: "active",
			PQCReady: pqcReady(f.algorithm), QSLScore: round2(algorithmQSL(f.algorithm)),
			Metadata: md, FirstSeen: now, LastSeen: now,
		}
		if secretKinds[f.kind] {
			a.Classification, a.PQCReady, a.QSLScore = "exposed", false, 0
			md["fingerprint_sha256_prefix"] = f.fingerprint
		} else {
			a.Classification = classifyAlgorithm(f.algorithm)
			md["fingerprint"] = f.fingerprint
		}
		if na, ok := f.meta["not_after"].(string); ok && parseTimeString(na).Before(now) {
			a.Status = "expired"
		}
		out = append(out, a)
	}
	return out
}
