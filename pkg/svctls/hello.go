package svctls

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	pkgcrypto "vecta-kms/pkg/crypto"
)

// probeGroupHello reports whether the TLS 1.3 server at addr selects group
// when a client offers only it, from the server's first flight alone. It
// exists for X25519 in FIPS mode, where Go's TLS won't offer it: the probe
// builds the ClientHello itself and reads the ServerHello. It performs no
// key exchange and no cryptography; the key share is 32 random bytes, which
// the server treats as a peer's X25519 public key. The connection is closed
// after the server's first record.
//
//   - ServerHello whose key_share names group: accepted.
//   - HelloRetryRequest (asking for another group), a ServerHello naming
//     another group, or a handshake_failure alert: not accepted.
func probeGroupHello(ctx context.Context, addr, serverName string, group tls.CurveID) (bool, error) {
	if group != tls.X25519 {
		return false, fmt.Errorf("hello probe supports X25519 only, not %s", group)
	}
	hello, err := clientHello(serverName, group)
	if err != nil {
		return false, err
	}
	d := net.Dialer{Timeout: 5 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return false, err
	}
	defer conn.Close() //nolint:errcheck
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write(hello); err != nil {
		return false, err
	}
	return readServerHello(conn, group)
}

// helloRetryRandom marks a HelloRetryRequest (RFC 8446, 4.1.3).
var helloRetryRandom = []byte{
	0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
	0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
}

const (
	extServerName        = 0x0000
	extSupportedGroups   = 0x000a
	extSignatureAlgs     = 0x000d
	extSupportedVersions = 0x002b
	extKeyShare          = 0x0033
)

func u16(b *bytes.Buffer, v int) { _ = binary.Write(b, binary.BigEndian, uint16(v)) }

func ext(b *bytes.Buffer, typ int, body []byte) {
	u16(b, typ)
	u16(b, len(body))
	b.Write(body)
}

// clientHello is a TLS 1.3 ClientHello record offering only group.
func clientHello(serverName string, group tls.CurveID) ([]byte, error) {
	random, err := pkgcrypto.RandomBytes(32)
	if err != nil {
		return nil, err
	}
	session, err := pkgcrypto.RandomBytes(32)
	if err != nil {
		return nil, err
	}
	share, err := pkgcrypto.RandomBytes(32)
	if err != nil {
		return nil, err
	}
	var exts bytes.Buffer
	if serverName != "" && net.ParseIP(serverName) == nil {
		var sni bytes.Buffer
		u16(&sni, len(serverName)+3)
		sni.WriteByte(0) // host_name
		u16(&sni, len(serverName))
		sni.WriteString(serverName)
		ext(&exts, extServerName, sni.Bytes())
	}
	ext(&exts, extSupportedVersions, []byte{2, 0x03, 0x04})
	ext(&exts, extSupportedGroups, []byte{0, 2, byte(group >> 8), byte(group)})
	var sigs bytes.Buffer
	algs := []int{0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601}
	u16(&sigs, 2*len(algs))
	for _, a := range algs {
		u16(&sigs, a)
	}
	ext(&exts, extSignatureAlgs, sigs.Bytes())
	var ks bytes.Buffer
	u16(&ks, 4+len(share))
	u16(&ks, int(group))
	u16(&ks, len(share))
	ks.Write(share)
	ext(&exts, extKeyShare, ks.Bytes())

	var body bytes.Buffer
	u16(&body, 0x0303) // legacy_version
	body.Write(random)
	body.WriteByte(byte(len(session)))
	body.Write(session)
	u16(&body, 4)
	u16(&body, 0x1301)       // TLS_AES_128_GCM_SHA256
	u16(&body, 0x1302)       // TLS_AES_256_GCM_SHA384
	body.Write([]byte{1, 0}) // compression: null
	u16(&body, exts.Len())
	body.Write(exts.Bytes())

	var hs bytes.Buffer
	hs.WriteByte(1) // client_hello
	hs.Write([]byte{byte(body.Len() >> 16), byte(body.Len() >> 8), byte(body.Len())})
	hs.Write(body.Bytes())

	var rec bytes.Buffer
	rec.Write([]byte{22, 0x03, 0x01}) // handshake record
	u16(&rec, hs.Len())
	rec.Write(hs.Bytes())
	return rec.Bytes(), nil
}

var errMalformedHello = errors.New("malformed server response")

// readServerHello reads the server's first record and reports whether it
// selected group.
func readServerHello(r io.Reader, group tls.CurveID) (bool, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return false, err
	}
	n := int(binary.BigEndian.Uint16(hdr[3:5]))
	if n == 0 || n > 1<<14+256 {
		return false, errMalformedHello
	}
	rec := make([]byte, n)
	if _, err := io.ReadFull(r, rec); err != nil {
		return false, err
	}
	switch hdr[0] {
	case 21: // alert: the server refused the offer
		return false, nil
	case 22:
	default:
		return false, errMalformedHello
	}
	// handshake: type(1) len(3) version(2) random(32) session(1+n) suite(2) comp(1) exts(2+n)
	if len(rec) < 4+2+32+1 || rec[0] != 2 {
		return false, errMalformedHello
	}
	p := rec[4:]
	if bytes.Equal(p[2:34], helloRetryRandom) {
		return false, nil
	}
	p = p[34:]
	sl := int(p[0])
	if len(p) < 1+sl+3+2 {
		return false, errMalformedHello
	}
	p = p[1+sl+3:]
	el := int(binary.BigEndian.Uint16(p[:2]))
	p = p[2:]
	if len(p) < el {
		return false, errMalformedHello
	}
	p = p[:el]
	for len(p) >= 4 {
		typ, l := binary.BigEndian.Uint16(p[:2]), int(binary.BigEndian.Uint16(p[2:4]))
		if len(p) < 4+l {
			return false, errMalformedHello
		}
		if typ == extKeyShare && l >= 2 {
			return tls.CurveID(binary.BigEndian.Uint16(p[4:6])) == group, nil
		}
		p = p[4+l:]
	}
	return false, errMalformedHello
}
