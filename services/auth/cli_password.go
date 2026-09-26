package main

import (
	"context"
	"encoding/base64"
	"errors"
	"log"
	"net/http"
	"strings"
	"time"

	pkgauth "vecta-kms/pkg/auth"
	pkgcrypto "vecta-kms/pkg/crypto"
)

// retiredCLIPassword shipped in services/hsm-integration/README.md and as the
// CLI user's seed password, so it is public. The CLI user's password is also
// its SSH password on the hsm-integration container. It is kept here only to
// refuse it and to find accounts still using it; make conformance
// (no-retired-public-secret) allows it on this marked line alone.
const retiredCLIPassword = "VectaCLI@2026" // conformance:retired-public-secret

func isRetiredCLIPassword(password string) bool {
	return strings.TrimSpace(password) == retiredCLIPassword
}

// validateCLIBootstrapPassword refuses a public AUTH_BOOTSTRAP_CLI_PASSWORD
// (docs/SECURITY/SECURE_DEFAULTS.md). The error never contains the value.
func validateCLIBootstrapPassword(password string) error {
	if isRetiredCLIPassword(password) {
		return errors.New("AUTH_BOOTSTRAP_CLI_PASSWORD is a public value that shipped in the repository; remove it to have one generated")
	}
	return nil
}

// revokeRetiredCLIPasswords gives every CLI user still holding the retired
// public password a random one nobody knows (with a forced change), audits
// it, and locks the copy on the hsm-integration container. An operator sets a
// new password in user management before the next CLI session.
func revokeRetiredCLIPasswords(ctx context.Context, store Store, logger *log.Logger, audit AuditPublisher, lockSSH func(ctx context.Context, username string) error) int {
	tenants, err := store.ListTenants(ctx)
	if err != nil {
		logger.Printf("bootstrap: list tenants for CLI password check: %v", err)
		return 0
	}
	revoked := 0
	for _, tenant := range tenants {
		users, err := store.ListUsers(ctx, tenant.ID)
		if err != nil {
			logger.Printf("bootstrap: list users of %s for CLI password check: %v", tenant.ID, err)
			continue
		}
		for _, listed := range users {
			if !strings.EqualFold(strings.TrimSpace(listed.Role), "cli-user") {
				continue
			}
			// The listing leaves out password hashes.
			u, err := store.GetUserByUsername(ctx, tenant.ID, listed.Username)
			if err != nil || !VerifyPassword(u.Password, retiredCLIPassword) {
				continue
			}
			raw, err := pkgcrypto.RandomBytes(32)
			if err != nil {
				logger.Printf("bootstrap: generate replacement CLI password: %v", err)
				return revoked
			}
			hash, err := HashPassword(base64.RawURLEncoding.EncodeToString(raw))
			pkgcrypto.Zeroize(raw)
			if err != nil {
				logger.Printf("bootstrap: hash replacement CLI password: %v", err)
				return revoked
			}
			if err := store.UpdateUserPassword(ctx, tenant.ID, u.ID, hash, true); err != nil {
				logger.Printf("bootstrap: revoke public CLI password of %s/%s: %v", tenant.ID, u.Username, err)
				continue
			}
			revoked++
			sshLocked := "not_attempted"
			if lockSSH != nil {
				sshLocked = "locked"
				if err := lockSSH(ctx, u.Username); err != nil {
					sshLocked = "not_running" // the container locks the account itself on every start
				}
			}
			logger.Printf("bootstrap: SECURITY revoked the public default password of CLI user %s/%s", tenant.ID, u.Username)
			bootstrapAudit(ctx, audit, "audit.auth.cli_password_revoked", tenant.ID, map[string]any{
				"user_id": u.ID, "username": u.Username, "reason": "public_default_password",
				"ssh_account": sshLocked, "severity": "critical", "result": "success",
				"description": "the CLI user's password (also its hsm-integration SSH password) was a value published in the repository; replaced with a random one",
			})
		}
	}
	return revoked
}

// Scripts run in the hsm-integration container. User and password arrive in
// the exec's environment and reach chpasswd through bash's printf builtin, so
// neither is ever on a command line (CLAUDE.md rule 9).
const (
	sshPasswordSyncScript = `printf '%s:%s\n' "$VECTA_CLI_USER" "$VECTA_CLI_PASSWORD" | chpasswd`
	sshPasswordLockScript = `passwd -l "$VECTA_CLI_USER" >/dev/null`
)

func (h *Handler) cliHSMServiceName() string {
	return strings.TrimSpace(envOr("AUTH_CLI_HSM_SERVICE_NAME", "hsm-integration"))
}

// syncCLISSHPassword sets the verified CLI password as the SSH password on
// the hsm-integration container, and audits the outcome.
func (h *Handler) syncCLISSHPassword(tenantID, actorID, username, password string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	service := h.cliHSMServiceName()
	_, err := h.execComposeServiceCommandEnv(ctx, service, []string{"bash", "-c", sshPasswordSyncScript},
		[]string{"VECTA_CLI_USER=" + username, "VECTA_CLI_PASSWORD=" + password})
	data := map[string]any{"service_name": service, "cli_username": username, "actor_id": actorID, "result": "success"}
	if err != nil {
		logger.Printf("cli-session: SSH password not set on %s: %v", service, err)
		data["result"], data["reason"] = "failure", "container_exec_failed"
	}
	_ = h.publishAudit(ctx, "audit.auth.cli_ssh_password_synced", "", tenantID, data)
}

// lockCLISSHPassword locks the SSH password of username on the
// hsm-integration container (after a revocation).
func (h *Handler) lockCLISSHPassword(ctx context.Context, username string) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	_, err := h.execComposeServiceCommandEnv(ctx, h.cliHSMServiceName(), []string{"bash", "-c", sshPasswordLockScript},
		[]string{"VECTA_CLI_USER=" + username})
	return err
}

func (h *Handler) auditCLISessionRefused(r *http.Request, reqID string, claims *pkgauth.Claims, username, reason string) {
	_ = h.publishAudit(r.Context(), "audit.auth.cli_session_refused", reqID, claims.TenantID, map[string]any{
		"initiator_user_id": claims.UserID, "cli_username": username, "reason": reason, "result": "refused",
	})
}
