package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/bits"
	"net"
	"strings"
	"time"

	pkgcrypto "vecta-kms/pkg/crypto"
	"vecta-kms/pkg/cryptocatalog"
)

// SSH endpoints for the network scan (7.18.0-beta). The probe reads what an
// SSH server sends in the clear before any key is agreed (RFC 4253 §4.2,
// §7.1): its identification string and SSH_MSG_KEXINIT, which lists the key
// exchange, host key, cipher and MAC algorithms it offers. To read each host
// key, it starts one ECDH exchange per host key type (curve25519-sha256, or
// ecdh-sha2-nistp256/384 for a server in FIPS mode) and takes K_S from
// SSH_MSG_KEX_ECDH_REPLY (RFC 5656 §4, RFC 8731), then disconnects, as
// ssh-keyscan does. Nothing is authenticated and no shared secret or session
// key is computed: the client's ephemeral value is random bytes from
// pkg/crypto (X25519) or a fresh pkg/crypto P-256/P-384 point whose private
// half is discarded, so discovery behaves the same in every FIPS mode.

const (
	sshMsgDisconnect   = 1
	sshMsgKexInit      = 20
	sshMsgKexECDHInit  = 30
	sshMsgKexECDHReply = 31
	sshMaxPacket       = 35000
	sshMaxNames        = 64
	sshMaxNameLen      = 64
	sshClientIdent     = "SSH-2.0-VectaKMS_Discovery"
)

var errNotSSH = errors.New("not an SSH-2.0 server")

type sshProbe struct {
	banner  string
	kexInit [10][]string // the ten name-lists of the server's SSH_MSG_KEXINIT
	// keys maps a host key type (ssh-rsa, ssh-ed25519, ecdsa-sha2-nistp256)
	// to the key the server presented for it.
	keys    map[string]sshHostKey
	keyErrs map[string]string
}

type sshHostKey struct {
	algorithm   string // catalogue name read from the key (RSA-3072, ED25519)
	fingerprint string // SHA256:<base64>, as ssh-keygen -l prints it
}

func (p sshProbe) kex() []string      { return p.kexInit[0] }
func (p sshProbe) hostAlgs() []string { return p.kexInit[1] }
func (p sshProbe) ciphers() []string  { return p.kexInit[3] } // server to client
func (p sshProbe) macs() []string     { return p.kexInit[5] }

type sshConn struct {
	conn   net.Conn
	r      *bufio.Reader
	banner string
	kex    [10][]string
}

func dialSSH(ctx context.Context, endpoint string, timeout time.Duration, guard dialControl) (*sshConn, error) {
	dctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := (&net.Dialer{Control: guard}).DialContext(dctx, "tcp", endpoint)
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))
	c := &sshConn{conn: conn, r: bufio.NewReader(conn)}
	if _, err := io.WriteString(conn, sshClientIdent+"\r\n"); err != nil {
		conn.Close() //nolint:errcheck
		return nil, err
	}
	if c.banner, err = readSSHIdent(c.r); err != nil {
		conn.Close() //nolint:errcheck
		return nil, err
	}
	payload, err := c.readPacket()
	if err == nil {
		c.kex, err = parseKexInit(payload)
	}
	if err != nil {
		conn.Close() //nolint:errcheck
		return nil, err
	}
	return c, nil
}

// readSSHIdent returns the server's identification line; RFC 4253 lets a
// server send other lines before it. A line longer than the read buffer
// ends the probe.
func readSSHIdent(r *bufio.Reader) (string, error) {
	for i := 0; i < 32; i++ {
		raw, err := r.ReadSlice('\n')
		if err != nil {
			return "", fmt.Errorf("%w: %v", errNotSSH, err)
		}
		line := strings.TrimRight(string(raw), "\r\n")
		if len(line) > 255 { // RFC 4253 §4.2
			return "", fmt.Errorf("%w: identification line too long", errNotSSH)
		}
		if strings.HasPrefix(line, "SSH-") {
			if !strings.HasPrefix(line, "SSH-2.0-") && !strings.HasPrefix(line, "SSH-1.99-") {
				return "", fmt.Errorf("%w: %s", errNotSSH, line)
			}
			return line, nil
		}
	}
	return "", errNotSSH
}

// readPacket reads one unencrypted binary packet (RFC 4253 §6).
func (c *sshConn) readPacket() ([]byte, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(c.r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:4])
	pad := uint32(hdr[4])
	if n < 5 || n > sshMaxPacket || pad+1 > n {
		return nil, fmt.Errorf("%w: bad packet length", errNotSSH)
	}
	body := make([]byte, n-1)
	if _, err := io.ReadFull(c.r, body); err != nil {
		return nil, err
	}
	payload := body[:n-1-pad]
	if len(payload) > 0 && payload[0] == sshMsgDisconnect {
		return nil, errors.New("server disconnected")
	}
	return payload, nil
}

func (c *sshConn) writePacket(payload []byte) error {
	pad := 8 - (5+len(payload))%8
	if pad < 4 {
		pad += 8
	}
	buf := make([]byte, 5+len(payload)+pad)
	binary.BigEndian.PutUint32(buf, uint32(1+len(payload)+pad))
	buf[4] = byte(pad)
	copy(buf[5:], payload)
	if _, err := pkgcrypto.Reader.Read(buf[5+len(payload):]); err != nil {
		return err
	}
	_, err := c.conn.Write(buf)
	return err
}

func parseKexInit(p []byte) ([10][]string, error) {
	var lists [10][]string
	if len(p) < 17 || p[0] != sshMsgKexInit {
		return lists, fmt.Errorf("%w: no KEXINIT", errNotSSH)
	}
	rest := p[17:]
	for i := range lists {
		s, r, ok := sshString(rest)
		if !ok {
			return lists, fmt.Errorf("%w: truncated KEXINIT", errNotSSH)
		}
		// A server chooses these bytes: keep at most sshMaxNames names
		// of at most sshMaxNameLen bytes each.
		for _, n := range strings.Split(string(s), ",") {
			if n != "" && len(n) <= sshMaxNameLen && len(lists[i]) < sshMaxNames {
				lists[i] = append(lists[i], n)
			}
		}
		rest = r
	}
	return lists, nil
}

func sshString(b []byte) ([]byte, []byte, bool) {
	if len(b) < 4 {
		return nil, nil, false
	}
	n := binary.BigEndian.Uint32(b)
	if uint64(n) > uint64(len(b)-4) {
		return nil, nil, false
	}
	return b[4 : 4+n], b[4+n:], true
}

func appendSSHString(b []byte, s []byte) []byte {
	b = binary.BigEndian.AppendUint32(b, uint32(len(s)))
	return append(b, s...)
}

// fetchHostKey runs the exchange up to the server's reply and returns the
// host key blob it presented for hostAlg.
func fetchHostKey(ctx context.Context, endpoint string, timeout time.Duration, guard dialControl, kex, hostAlg string) ([]byte, error) {
	c, err := dialSSH(ctx, endpoint, timeout, guard)
	if err != nil {
		return nil, err
	}
	defer c.conn.Close() //nolint:errcheck
	msg := make([]byte, 17)
	msg[0] = sshMsgKexInit
	if _, err := pkgcrypto.Reader.Read(msg[1:17]); err != nil {
		return nil, err
	}
	// Offer only what the server listed, so the exchange settles on kex
	// and hostAlg.
	lists := c.kex
	lists[0], lists[1], lists[8], lists[9] = []string{kex}, []string{hostAlg}, nil, nil
	for _, l := range lists {
		msg = appendSSHString(msg, []byte(strings.Join(l, ",")))
	}
	msg = append(msg, 0, 0, 0, 0, 0) // first_kex_packet_follows, reserved
	if err := c.writePacket(msg); err != nil {
		return nil, err
	}
	eph, err := sshEphemeral(kex)
	if err != nil {
		return nil, err
	}
	if err := c.writePacket(appendSSHString([]byte{sshMsgKexECDHInit}, eph)); err != nil {
		return nil, err
	}
	for i := 0; i < 8; i++ {
		p, err := c.readPacket()
		if err != nil {
			return nil, err
		}
		if len(p) > 0 && p[0] == sshMsgKexECDHReply {
			ks, _, ok := sshString(p[1:])
			if !ok {
				return nil, errors.New("truncated KEX_ECDH_REPLY")
			}
			return ks, nil
		}
	}
	return nil, errors.New("no KEX_ECDH_REPLY")
}

// sshKeyReadKex: the exchanges a host key is read with, cheapest first.
var sshKeyReadKex = []string{"curve25519-sha256", "curve25519-sha256@libssh.org", "ecdh-sha2-nistp256", "ecdh-sha2-nistp384"}

// sshEphemeral is the client's public value for kex. Any 32 bytes are an
// X25519 public value; a NIST-curve server rejects a point not on the
// curve, so that one comes from a pkg/crypto key pair.
func sshEphemeral(kex string) ([]byte, error) {
	if strings.HasPrefix(kex, "curve25519") {
		b := make([]byte, 32)
		_, err := pkgcrypto.Reader.Read(b)
		return b, err
	}
	alg := map[string]string{"ecdh-sha2-nistp256": pkgcrypto.AlgECDSAP256, "ecdh-sha2-nistp384": pkgcrypto.AlgECDSAP384}[kex]
	if alg == "" {
		return nil, fmt.Errorf("no ephemeral for %s", kex)
	}
	kp, err := pkgcrypto.GenerateKeyPair(alg)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKIXPublicKey(kp.Public)
	if err != nil {
		return nil, err
	}
	var spki struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(der, &spki); err != nil {
		return nil, err
	}
	return spki.PublicKey.Bytes, nil // uncompressed point, SEC 1 §2.3.3
}

// sshHostKeyType groups the host key algorithms that share one key: the
// three RSA signature names all use the ssh-rsa key. Certificates are
// skipped (their key is listed under its plain type).
func sshHostKeyType(alg string) string {
	switch alg {
	case "rsa-sha2-512", "rsa-sha2-256", "ssh-rsa":
		return "ssh-rsa"
	}
	if strings.Contains(alg, "-cert-") {
		return ""
	}
	return alg
}

func probeSSH(ctx context.Context, endpoint string, timeout time.Duration, guard dialControl) (sshProbe, error) {
	c, err := dialSSH(ctx, endpoint, timeout, guard)
	if err != nil {
		return sshProbe{}, err
	}
	c.conn.Close() //nolint:errcheck
	p := sshProbe{banner: c.banner, kexInit: c.kex, keys: map[string]sshHostKey{}, keyErrs: map[string]string{}}
	kex := ""
	for _, k := range sshKeyReadKex {
		if containsString(p.kex(), k) {
			kex = k
			break
		}
	}
	for _, alg := range p.hostAlgs() {
		typ := sshHostKeyType(alg)
		if typ == "" {
			continue
		}
		if _, done := p.keys[typ]; done {
			continue
		}
		if _, failed := p.keyErrs[typ]; failed {
			continue
		}
		if kex == "" {
			p.keyErrs[typ] = "server offers no ECDH exchange to read the key with"
			continue
		}
		blob, err := fetchHostKey(ctx, endpoint, timeout, guard, kex, alg)
		if err != nil {
			p.keyErrs[typ] = err.Error()
			continue
		}
		sum := sha256.Sum256(blob)
		p.keys[typ] = sshHostKey{algorithm: sshKeyName(blob), fingerprint: "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])}
	}
	return p, nil
}

// sshKeyName names an SSH public key blob (RFC 4253 §6.6, RFC 5656 §3.1,
// RFC 8709) by the key it holds; RSA and DSA sizes come from the modulus.
func sshKeyName(blob []byte) string {
	typ, rest, ok := sshString(blob)
	if !ok {
		return "UNKNOWN"
	}
	switch t := string(typ); {
	case t == "ssh-rsa":
		if _, rest, ok = sshString(rest); ok { // e
			if n, _, ok := sshString(rest); ok {
				return fmt.Sprintf("RSA-%d", mpintBits(n))
			}
		}
	case t == "ssh-dss":
		if p, _, ok := sshString(rest); ok {
			return fmt.Sprintf("DSA-%d", mpintBits(p))
		}
	case t == "ssh-ed25519" || t == "sk-ssh-ed25519@openssh.com":
		return "ED25519"
	case t == "ssh-ed448":
		return "ED448"
	case strings.HasPrefix(t, "ecdsa-sha2-nistp") || strings.HasPrefix(t, "sk-ecdsa-sha2-nistp"):
		curve := strings.TrimSuffix(t[strings.Index(t, "nistp")+5:], "@openssh.com")
		return "ECDSA-P" + curve
	}
	return "UNKNOWN"
}

func mpintBits(b []byte) int {
	for len(b) > 0 && b[0] == 0 {
		b = b[1:]
	}
	if len(b) == 0 {
		return 0
	}
	return (len(b)-1)*8 + bits.Len8(b[0])
}

// sshKexName maps an SSH key exchange method to its catalogue name and the
// hash it uses for the exchange. A method whose group the name doesn't fix
// (group exchange) or that the catalogue doesn't list stays not assessed.
func sshKexName(m string) (string, string) {
	m = strings.TrimSuffix(strings.TrimSuffix(m, "@libssh.org"), "@openssh.com")
	hash := ""
	if i := strings.LastIndex(m, "-sha"); i >= 0 {
		hash = strings.ToUpper(m[i+1:])
	}
	switch {
	case strings.HasPrefix(m, "mlkem768x25519"):
		return "X25519-ML-KEM-768-HYBRID", hash
	case strings.HasPrefix(m, "mlkem768nistp256"):
		return "ECDH-P256-ML-KEM-768-HYBRID", hash
	case strings.HasPrefix(m, "mlkem1024nistp384"):
		return "ECDH-P384-ML-KEM-1024-HYBRID", hash
	case strings.HasPrefix(m, "curve25519"):
		return "X25519", hash
	case strings.HasPrefix(m, "curve448"):
		return "X448", hash
	case strings.HasPrefix(m, "ecdh-sha2-nistp"):
		return "ECDH-P" + strings.TrimPrefix(m, "ecdh-sha2-nistp"), "SHA" + map[string]string{"256": "256", "384": "384", "521": "512"}[strings.TrimPrefix(m, "ecdh-sha2-nistp")]
	case strings.HasPrefix(m, "diffie-hellman-group-exchange"):
		return "DH-GROUP-EXCHANGE", hash
	case strings.HasPrefix(m, "diffie-hellman-group"):
		g := strings.TrimPrefix(m, "diffie-hellman-group")
		g = g[:strings.IndexByte(g+"-", '-')]
		if size, ok := map[string]string{"1": "1024", "14": "2048", "15": "3072", "16": "4096", "17": "6144", "18": "8192"}[g]; ok {
			return "DH-" + size, hash
		}
	}
	return strings.ToUpper(m), hash
}

// sshPseudoKex: names in the key exchange list that signal extensions, not
// methods (RFC 8308, the OpenSSH strict-kex marker).
func sshPseudoKex(m string) bool {
	return strings.HasPrefix(m, "ext-info-") || strings.HasPrefix(m, "kex-strict-")
}

// sshSymName maps an SSH cipher or MAC name to its catalogue name.
func sshSymName(n string) string {
	n = strings.TrimSuffix(strings.TrimSuffix(n, "@openssh.com"), "-etm")
	switch {
	case strings.HasPrefix(n, "aes"):
		// aes128-ctr, aes256-gcm
		if i := strings.IndexByte(n, '-'); i > 3 {
			return "AES-" + n[3:i] + "-" + strings.ToUpper(n[i+1:])
		}
	case n == "3des-cbc":
		return "3DES-CBC"
	case strings.HasPrefix(n, "arcfour"):
		return "RC4"
	case strings.HasPrefix(n, "chacha20"):
		return "CHACHA20-POLY1305"
	case strings.HasPrefix(n, "hmac-"):
		h := strings.ToUpper(strings.TrimSuffix(strings.TrimPrefix(n, "hmac-"), "-96"))
		return "HMAC-" + strings.Replace(h, "SHA2-", "SHA-", 1)
	}
	return strings.ToUpper(n)
}

// weakOffered lists the offered names the catalogue calls weak.
func weakOffered(names []string, name func(string) string) []string {
	out := []string{}
	for _, n := range names {
		if e, ok := cryptocatalog.Lookup(name(n)); ok && e.Weak {
			out = append(out, n)
		}
	}
	return out
}

// sshKexWeak: the method's group is weak, or its exchange hash is.
func sshKexWeak(m string) bool {
	alg, hash := sshKexName(m)
	if e, ok := cryptocatalog.Lookup(alg); ok && e.Weak {
		return true
	}
	e, ok := cryptocatalog.Lookup(hash)
	return ok && e.Weak
}

// strongestKex is the offered method a post-quantum-first client would
// pick: post-quantum before classical, then by security strength. Methods
// the catalogue doesn't assess rank last.
func strongestKex(methods []string) string {
	best, bestRank := "", -2
	for _, m := range methods {
		if sshPseudoKex(m) {
			continue
		}
		alg, _ := sshKexName(m)
		rank := -1
		if e, ok := cryptocatalog.Lookup(alg); ok && !sshKexWeak(m) {
			rank = e.SecurityBits
			if e.PostQuantum {
				rank += 1000
			}
		}
		if rank > bestRank {
			best, bestRank = alg, rank
		}
	}
	return best
}

func (s *Service) sshAssets(tenantID, scanID, ep string, p sshProbe) []CryptoAsset {
	now := s.now()
	kexOffered := []string{}
	weakKex := []string{}
	for _, m := range p.kex() {
		if sshPseudoKex(m) {
			continue
		}
		kexOffered = append(kexOffered, m)
		if sshKexWeak(m) {
			weakKex = append(weakKex, m)
		}
	}
	alg := defaultString(strongestKex(p.kex()), "UNKNOWN")
	out := []CryptoAsset{{
		ID: assetDeterministicID(tenantID, "network", "ssh_endpoint", ep, ep, ""), TenantID: tenantID, ScanID: scanID,
		AssetType: "ssh_endpoint", Name: ep, Location: ep, Source: "network",
		Algorithm: alg, StrengthBits: strengthBits(alg), Status: "active",
		Classification: classifyAlgorithm(alg), PQCReady: pqcReady(alg), QSLScore: round2(algorithmQSL(alg)),
		Metadata: map[string]interface{}{
			"protocol": "SSH-2.0", "server": strings.TrimPrefix(strings.TrimPrefix(p.banner, "SSH-2.0-"), "SSH-1.99-"),
			"key_exchange_offered": kexOffered, "weak_key_exchange_offered": weakKex,
			"host_key_algorithms": p.hostAlgs(), "ciphers_offered": p.ciphers(), "macs_offered": p.macs(),
			"weak_ciphers_offered": weakOffered(p.ciphers(), sshSymName), "weak_macs_offered": weakOffered(p.macs(), sshSymName),
			"selection": "strongest offered",
		},
		FirstSeen: now, LastSeen: now,
	}}
	seen := map[string]bool{}
	for _, a := range p.hostAlgs() {
		typ := sshHostKeyType(a)
		if typ == "" || seen[typ] {
			continue
		}
		seen[typ] = true
		k, ok := p.keys[typ]
		md := map[string]interface{}{"key_type": typ}
		if ok {
			md["fingerprint"] = k.fingerprint
		} else {
			// Without the key, the type still names the curve; an RSA or
			// DSA size stays not assessed.
			k.algorithm = map[string]string{"ssh-rsa": "RSA", "ssh-dss": "DSA"}[typ]
			if k.algorithm == "" {
				k.algorithm = sshKeyName(appendSSHString(nil, []byte(typ)))
			}
			md["key_error"] = p.keyErrs[typ]
		}
		out = append(out, CryptoAsset{
			ID: assetDeterministicID(tenantID, "network", "ssh_host_key", ep, ep, typ), TenantID: tenantID, ScanID: scanID,
			AssetType: "ssh_host_key", Name: ep + " " + typ, Location: ep, Source: "network",
			Algorithm: k.algorithm, StrengthBits: strengthBits(k.algorithm), Status: "active",
			Classification: classifyAlgorithm(k.algorithm), PQCReady: pqcReady(k.algorithm), QSLScore: round2(algorithmQSL(k.algorithm)),
			Metadata: md, FirstSeen: now, LastSeen: now,
		})
	}
	return out
}
