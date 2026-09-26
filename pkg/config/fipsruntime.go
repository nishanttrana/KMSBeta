package config

import (
	"context"
	"crypto/fips140"
	"database/sql"
	"errors"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib" // registers the "pgx" driver (as pkg/db)

	"vecta-kms/pkg/clusterstate"
	"vecta-kms/pkg/fips"
)

// FIPS runtime mode, platform-controlled (docs/SECURITY/FIPS.md).
//
// At startup every service reads the administrator's platform FIPS mode
// (governance table platform_fips_mode), re-executes itself with the matching
// GODEBUG=fips140 if needed, verifies the result, and reports the mode it runs
// in (platform_fips_observed). A watcher then polls the setting; when an
// administrator changes it, the service waits its restart tier and sends
// itself SIGTERM, so its normal graceful shutdown runs and the supervisor
// (Docker restart policy / systemd) starts it again in the new mode.

const fipsWatchInterval = 15 * time.Second

var fipsOnce sync.Once

type fipsModeStore interface {
	Desired(ctx context.Context) (string, error)
	ReportObserved(ctx context.Context, service, instance, mode, module string, validated bool, started time.Time) error
}

type sqlFIPSModeStore struct{ db *sql.DB }

func openFIPSModeStore() fipsModeStore {
	dsn := strings.TrimSpace(os.Getenv("POSTGRES_DSN"))
	if dsn == "" || getBool("SQLITE_FALLBACK", false) {
		return nil
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil
	}
	db.SetMaxOpenConns(1)
	return sqlFIPSModeStore{db: db}
}

// Desired returns the administrator's platform mode, "" if never set.
func (s sqlFIPSModeStore) Desired(ctx context.Context) (string, error) {
	var mode string
	err := s.db.QueryRowContext(ctx, `SELECT mode FROM platform_fips_mode WHERE id = 1`).Scan(&mode)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return strings.TrimSpace(mode), err
}

func (s sqlFIPSModeStore) ReportObserved(ctx context.Context, service, instance, mode, module string, validated bool, started time.Time) error {
	_, err := s.db.ExecContext(ctx, `
INSERT INTO platform_fips_observed (service, instance, mode, module_version, validated, started_at, updated_at)
VALUES ($1,$2,$3,$4,$5,$6,CURRENT_TIMESTAMP)
ON CONFLICT (service, instance) DO UPDATE SET mode = EXCLUDED.mode, module_version = EXCLUDED.module_version,
	validated = EXCLUDED.validated, started_at = EXCLUDED.started_at, updated_at = CURRENT_TIMESTAMP
`, service, instance, mode, module, validated, started.UTC())
	return err
}

func fipsServiceName() string { return filepath.Base(os.Args[0]) }

// RequireFIPSRuntime puts the process in the platform FIPS mode and stops it
// if that fails. Called from Load and NewHTTPServer so every service gets it
// by construction.
func RequireFIPSRuntime() {
	fipsOnce.Do(func() {
		store := openFIPSModeStore()
		if sq, ok := store.(sqlFIPSModeStore); ok {
			// The same small connection serves the cluster-role reader
			// (write forwarding, clusterforward.go).
			clusterstate.SetDefault(clusterstate.NewReader(sq.db))
		}
		desired := ""
		if store != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			d, err := store.Desired(ctx)
			cancel()
			if err != nil {
				log.Printf("fips: platform mode not readable (%v); using VECTA_FIPS_MODE", err)
			}
			desired = d
		}
		target, reexec, err := fips.Decide(desired, os.Getenv("VECTA_FIPS_MODE"), fips.Mode(), os.Getenv(fips.ReexecMarker) == "1")
		if err != nil {
			log.Fatalf("refusing to start: %v — see docs/SECURITY/FIPS.md", err)
		}
		if reexec {
			exe, err := os.Executable()
			if err == nil {
				log.Printf("fips: platform mode is %q; re-executing in that mode", target)
				err = syscall.Exec(exe, os.Args, fips.ReexecEnv(os.Environ(), target))
			}
			log.Fatalf("refusing to start: cannot re-execute in FIPS mode %q: %v", target, err)
		}
		if desired != "" {
			_ = os.Setenv("VECTA_FIPS_MODE", target)
		}
		if err := fips.VerifyRuntime(); err != nil {
			log.Fatalf("refusing to start: %v — see docs/SECURITY/FIPS.md", err)
		}
		mode := fips.Mode()
		log.Printf("fips: mode=%s module=%s validated=%t", mode, fips140.Version(), fips.ModuleValidated())
		if store == nil {
			return
		}
		host, _ := os.Hostname()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = store.ReportObserved(ctx, fipsServiceName(), host, mode, fips140.Version(), fips.ModuleValidated(), time.Now())
		cancel()
		w := fipsWatcher{
			store: store, service: fipsServiceName(), running: mode, interval: fipsWatchInterval,
			delay: fips.RestartDelay, sleep: time.Sleep,
			stop: func() { _ = syscall.Kill(os.Getpid(), syscall.SIGTERM) },
		}
		go w.run()
	})
}

type fipsWatcher struct {
	store    fipsModeStore
	service  string
	running  string
	interval time.Duration
	delay    func(string) time.Duration
	sleep    func(time.Duration)
	stop     func()
	quit     <-chan struct{} // nil in production (runs for the process lifetime)
}

// run polls the platform mode and, on a change, waits the service's restart
// tier, re-confirms, and stops the process for a supervised restart.
func (w fipsWatcher) run() {
	for {
		select {
		case <-w.quit:
			return
		default:
		}
		w.sleep(w.interval)
		desired := w.desired()
		if desired == "" || desired == w.running || !fips.ValidMode(desired) {
			continue
		}
		d := w.delay(w.service)
		log.Printf("fips: platform mode changed %s -> %s; %s restarts in %s to apply it", w.running, desired, w.service, d)
		w.sleep(d)
		if w.desired() != desired {
			log.Printf("fips: platform mode changed again; re-evaluating")
			continue
		}
		w.stop()
		return
	}
}

func (w fipsWatcher) desired() string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	d, err := w.store.Desired(ctx)
	if err != nil {
		return ""
	}
	return d
}
