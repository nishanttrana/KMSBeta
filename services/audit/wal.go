package main

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type WALRecord struct {
	Type       string `json:"type"` // publish|ingest
	Subject    string `json:"subject"`
	PayloadB64 string `json:"payload_b64"`
	Timestamp  string `json:"timestamp"`
	HMAC       string `json:"hmac"`
}

type WALBuffer struct {
	path     string
	maxBytes int64
	hmacKey  []byte
	mu       sync.Mutex
}

func NewWALBuffer(path string, maxSizeMB int64, hmacKey []byte) *WALBuffer {
	if maxSizeMB <= 0 {
		maxSizeMB = 512
	}
	return &WALBuffer{
		path:     path,
		maxBytes: maxSizeMB * 1024 * 1024,
		hmacKey:  hmacKey,
	}
}

func (w *WALBuffer) Append(recType string, subject string, payload []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := os.MkdirAll(filepath.Dir(w.path), 0o755); err != nil {
		return err
	}
	if st, err := os.Stat(w.path); err == nil && st.Size() >= w.maxBytes {
		return errors.New("wal max size reached")
	}
	rec := WALRecord{
		Type:       recType,
		Subject:    subject,
		PayloadB64: base64.StdEncoding.EncodeToString(payload),
		Timestamp:  time.Now().UTC().Format(time.RFC3339Nano),
	}
	rec.HMAC = w.sign(rec)
	raw, _ := json.Marshal(rec)
	f, err := os.OpenFile(w.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer f.Close() //nolint:errcheck
	if _, err := f.Write(append(raw, '\n')); err != nil {
		return err
	}
	return nil
}

func (w *WALBuffer) Drain(processor func(rec WALRecord, payload []byte) error) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	f, err := os.OpenFile(w.path, os.O_RDONLY|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	defer f.Close() //nolint:errcheck

	var pending []WALRecord
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var rec WALRecord
		if err := json.Unmarshal(line, &rec); err != nil {
			continue
		}
		if rec.HMAC != w.sign(rec) {
			continue
		}
		payload, err := base64.StdEncoding.DecodeString(rec.PayloadB64)
		if err != nil {
			continue
		}
		if err := processor(rec, payload); err != nil {
			pending = append(pending, rec)
		}
	}
	if err := sc.Err(); err != nil {
		return err
	}
	return w.rewrite(pending)
}

func (w *WALBuffer) rewrite(records []WALRecord) error {
	tmp := w.path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	for _, rec := range records {
		raw, _ := json.Marshal(rec)
		if _, err := f.Write(append(raw, '\n')); err != nil {
			_ = f.Close()
			return err
		}
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, w.path)
}

func (w *WALBuffer) sign(rec WALRecord) string {
	m := hmac.New(sha256.New, w.hmacKey)
	_, _ = m.Write([]byte(rec.Type))
	_, _ = m.Write([]byte("|"))
	_, _ = m.Write([]byte(rec.Subject))
	_, _ = m.Write([]byte("|"))
	_, _ = m.Write([]byte(rec.PayloadB64))
	_, _ = m.Write([]byte("|"))
	_, _ = m.Write([]byte(rec.Timestamp))
	return base64.StdEncoding.EncodeToString(m.Sum(nil))
}
