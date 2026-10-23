// Command edge-agent runs on an edge or IoT device: it enrols with the KMS,
// leases data keys, encrypts and decrypts offline under them, and reports
// what it did (docs/SECURITY/EDGE_DEVICES.md).
//
//	edge-agent enroll  -server https://<kms>/svc/ekm -token-file F [-ca bundle.pem] [-dir D]
//	edge-agent lease   -key <key-id> [-ttl seconds] [-dir D]
//	edge-agent encrypt -lease <lease-id> -in F -out G [-dir D]
//	edge-agent decrypt -in G -out F [-dir D]
//	edge-agent sync    [-dir D]
//	edge-agent status  [-dir D]
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

const defaultDir = "/var/lib/vecta-edge"

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "edge-agent:", err)
		os.Exit(1)
	}
}

func run(args []string, out io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf("a command: enroll, lease, encrypt, decrypt, sync or status")
	}
	cmd := args[0]
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	dir := fs.String("dir", defaultDir, "state directory (mode 0700)")
	server := fs.String("server", "", "the KMS EKM endpoint, https://<host>/svc/ekm")
	tokenFile := fs.String("token-file", "", "file holding the one-use registration token")
	ca := fs.String("ca", "", "PEM bundle of the KMS certificate's CA, when it is the KMS's own")
	key := fs.String("key", "", "key ID to lease")
	ttl := fs.Int64("ttl", 0, "lease length in seconds (default: the device's longest)")
	leaseID := fs.String("lease", "", "lease to encrypt under")
	in := fs.String("in", "", "input file")
	outPath := fs.String("out", "", "output file")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if cmd == "enroll" {
		a, err := enroll(ctx, *dir, *server, *tokenFile, *ca)
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "enrolled as device %s\n", a.st.DeviceID)
		return nil
	}
	a, err := loadAgent(*dir)
	if err != nil {
		return err
	}
	switch cmd {
	case "lease":
		l, err := a.takeLease(ctx, strings.TrimSpace(*key), *ttl)
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "lease %s for key %s (version %d), until %s\n", l.ID, l.KeyID, l.KeyVersion, l.ExpiresAt.Format(time.RFC3339))
	case "encrypt", "decrypt":
		if *in == "" || *outPath == "" {
			return fmt.Errorf("-in and -out are required")
		}
		data, err := os.ReadFile(*in)
		if err != nil {
			return err
		}
		var result []byte
		if cmd == "encrypt" {
			result, err = a.encrypt(strings.TrimSpace(*leaseID), data)
		} else {
			result, err = a.decrypt(data)
		}
		if err != nil {
			return err
		}
		if err := os.WriteFile(*outPath, result, 0o600); err != nil {
			return err
		}
	case "sync":
		res, err := a.sync(ctx)
		if res.Revoked {
			fmt.Fprintln(out, "this device was revoked: every lease was removed")
		}
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "sent %d receipts; removed leases: %s\n", res.Sent, strings.Join(res.Dropped, ", "))
	case "status":
		pending, err := a.pending()
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "device %s (tenant %s), revoked: %v, receipts to send: %d\n", a.st.DeviceID, a.st.TenantID, a.st.Revoked, len(pending))
		entries, _ := os.ReadDir(a.dir + "/leases")
		for _, e := range entries {
			if l, err := a.loadLease(strings.TrimSuffix(e.Name(), ".json")); err == nil {
				fmt.Fprintf(out, "  lease %s key %s until %s\n", l.ID, l.KeyID, l.ExpiresAt.Format(time.RFC3339))
			}
		}
	default:
		return fmt.Errorf("unknown command %q", cmd)
	}
	return nil
}
