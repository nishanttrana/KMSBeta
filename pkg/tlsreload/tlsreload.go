// Package tlsreload serves a server certificate from files another service
// writes, re-reading them when they change. The external listeners (KMIP,
// Azure Managed HSM external key management) serve the certificate certs
// writes for the source a root administrator chose
// (docs/SECURITY/INTERNAL_TLS.md, "Edge certificate").
package tlsreload

import (
	"crypto/tls"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

// Reloader serves CertFile/KeyFile, checking them for a change at most once
// a second. A replacement that doesn't load keeps the one in force.
type Reloader struct {
	CertFile, KeyFile string
	// Name labels log lines ("KMIP server certificate").
	Name string
	Logf func(string, ...interface{})

	mu      sync.Mutex
	cert    *tls.Certificate
	stamp   string
	checked time.Time
}

func fileStamp(paths ...string) (string, error) {
	var b strings.Builder
	for _, p := range paths {
		st, err := os.Stat(p)
		if err != nil {
			return "", err
		}
		fmt.Fprintf(&b, "%s:%d:%d;", p, st.Size(), st.ModTime().UnixNano())
	}
	return b.String(), nil
}

// Load reads the files now.
func (r *Reloader) Load() error {
	stamp, err := fileStamp(r.CertFile, r.KeyFile)
	if err != nil {
		return err
	}
	cert, err := tls.LoadX509KeyPair(r.CertFile, r.KeyFile)
	if err != nil {
		return err
	}
	r.mu.Lock()
	r.cert, r.stamp = &cert, stamp
	r.mu.Unlock()
	return nil
}

func (r *Reloader) logf(format string, args ...interface{}) {
	if r.Logf != nil {
		r.Logf(format, args...)
	}
}

// GetCertificate is tls.Config.GetCertificate.
func (r *Reloader) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	r.mu.Lock()
	due := time.Since(r.checked) >= time.Second
	if due {
		r.checked = time.Now()
	}
	cur, stamp := r.cert, r.stamp
	r.mu.Unlock()
	if due {
		if now, err := fileStamp(r.CertFile, r.KeyFile); err == nil && now != stamp {
			if err := r.Load(); err != nil {
				r.logf("%s changed but did not load (%v); keeping the current one", r.Name, err)
			} else {
				r.mu.Lock()
				cur = r.cert
				r.mu.Unlock()
				r.logf("%s reloaded", r.Name)
			}
		}
	}
	if cur == nil {
		return nil, errors.New("no " + r.Name)
	}
	return cur, nil
}
