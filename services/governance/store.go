package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	pkgdb "vecta-kms/pkg/db"
)

var errNotFound = errors.New("not found")

type Store interface {
	CreatePolicy(ctx context.Context, p ApprovalPolicy) error
	UpdatePolicy(ctx context.Context, p ApprovalPolicy) error
	DeletePolicy(ctx context.Context, tenantID string, policyID string) error
	GetPolicy(ctx context.Context, tenantID string, policyID string) (ApprovalPolicy, error)
	ListPolicies(ctx context.Context, tenantID string, scope string, status string) ([]ApprovalPolicy, error)
	FindPolicyForAction(ctx context.Context, tenantID string, policyID string, action string) (ApprovalPolicy, error)

	CreateApprovalRequest(ctx context.Context, req ApprovalRequest, tokens []ApprovalToken) error
	GetApprovalRequest(ctx context.Context, tenantID string, requestID string) (ApprovalRequest, error)
	ListApprovalRequests(ctx context.Context, tenantID string, status string, targetType string, targetID string) ([]ApprovalRequest, error)
	ListApprovalVotes(ctx context.Context, tenantID string, requestID string) ([]ApprovalVote, error)
	CancelApprovalRequest(ctx context.Context, tenantID string, requestID string, requesterID string) error
	ListPendingByApprover(ctx context.Context, tenantID string, approverEmail string) ([]ApprovalRequest, error)
	CountPendingByApprover(ctx context.Context, tenantID string, approverEmail string) (int, error)
	ConsumeToken(ctx context.Context, requestID string, tokenRaw string, expectedAction string) (ApprovalToken, error)
	ApplyVote(ctx context.Context, req ApprovalRequest, policy ApprovalPolicy, vote ApprovalVote) (ApprovalRequest, error)
	ExpirePendingRequests(ctx context.Context, now time.Time) ([]ApprovalRequest, error)
	GetSettings(ctx context.Context, tenantID string) (GovernanceSettings, error)
	UpsertSettings(ctx context.Context, s GovernanceSettings) error
	GetSystemState(ctx context.Context, tenantID string) (GovernanceSystemState, error)
	UpsertSystemState(ctx context.Context, state GovernanceSystemState) error
}

type SQLStore struct {
	db *pkgdb.DB
}

func NewSQLStore(db *pkgdb.DB) *SQLStore {
	return &SQLStore{db: db}
}

func (s *SQLStore) CreatePolicy(ctx context.Context, p ApprovalPolicy) error {
	triggerActions, _ := json.Marshal(p.TriggerActions)
	approverRoles, _ := json.Marshal(p.ApproverRoles)
	approverUsers, _ := json.Marshal(p.ApproverUsers)
	escalationTo, _ := json.Marshal(p.EscalationTo)
	channels, _ := json.Marshal(p.NotificationChannels)
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO approval_policies (
    id, tenant_id, name, description, scope, trigger_actions, quorum_mode, required_approvals, total_approvers,
    approver_roles, approver_users, timeout_hours, escalation_hours, escalation_to, retention_days,
    notification_channels, status, created_at
) VALUES (
    $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,CURRENT_TIMESTAMP
)
`, p.ID, p.TenantID, p.Name, nullable(p.Description), p.Scope, triggerActions, p.QuorumMode, p.RequiredApprovals, p.TotalApprovers,
		approverRoles, nullableJSON(approverUsers), p.TimeoutHours, nullableInt(p.EscalationHours), nullableJSON(escalationTo),
		p.RetentionDays, channels, p.Status)
	return err
}

func (s *SQLStore) UpdatePolicy(ctx context.Context, p ApprovalPolicy) error {
	triggerActions, _ := json.Marshal(p.TriggerActions)
	approverRoles, _ := json.Marshal(p.ApproverRoles)
	approverUsers, _ := json.Marshal(p.ApproverUsers)
	escalationTo, _ := json.Marshal(p.EscalationTo)
	channels, _ := json.Marshal(p.NotificationChannels)
	res, err := s.db.SQL().ExecContext(ctx, `
UPDATE approval_policies
SET name=$1, description=$2, scope=$3, trigger_actions=$4, quorum_mode=$5, required_approvals=$6, total_approvers=$7,
    approver_roles=$8, approver_users=$9, timeout_hours=$10, escalation_hours=$11, escalation_to=$12,
    retention_days=$13, notification_channels=$14, status=$15
WHERE tenant_id=$16 AND id=$17
`, p.Name, nullable(p.Description), p.Scope, triggerActions, p.QuorumMode, p.RequiredApprovals, p.TotalApprovers,
		approverRoles, nullableJSON(approverUsers), p.TimeoutHours, nullableInt(p.EscalationHours), nullableJSON(escalationTo),
		p.RetentionDays, channels, p.Status, p.TenantID, p.ID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errNotFound
	}
	return nil
}

func (s *SQLStore) DeletePolicy(ctx context.Context, tenantID string, policyID string) error {
	res, err := s.db.SQL().ExecContext(ctx, `DELETE FROM approval_policies WHERE tenant_id=$1 AND id=$2`, tenantID, policyID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errNotFound
	}
	return nil
}

func (s *SQLStore) GetPolicy(ctx context.Context, tenantID string, policyID string) (ApprovalPolicy, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT id, tenant_id, name, COALESCE(description,''), scope, trigger_actions, required_approvals, total_approvers,
       COALESCE(quorum_mode,'threshold'),
       approver_roles, COALESCE(approver_users,'[]'), timeout_hours, COALESCE(escalation_hours,0), COALESCE(escalation_to,'[]'),
       retention_days, notification_channels, status, created_at
FROM approval_policies
WHERE tenant_id=$1 AND id=$2
`, tenantID, policyID)
	p, err := scanPolicy(row)
	if errors.Is(err, sql.ErrNoRows) {
		return ApprovalPolicy{}, errNotFound
	}
	return p, err
}

func (s *SQLStore) ListPolicies(ctx context.Context, tenantID string, scope string, status string) ([]ApprovalPolicy, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT id, tenant_id, name, COALESCE(description,''), scope, trigger_actions, required_approvals, total_approvers,
       COALESCE(quorum_mode,'threshold'),
       approver_roles, COALESCE(approver_users,'[]'), timeout_hours, COALESCE(escalation_hours,0), COALESCE(escalation_to,'[]'),
       retention_days, notification_channels, status, created_at
FROM approval_policies
WHERE tenant_id=$1
  AND ($2='' OR scope=$2)
  AND ($3='' OR status=$3)
ORDER BY created_at DESC
`, tenantID, strings.TrimSpace(scope), strings.TrimSpace(status))
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	var out []ApprovalPolicy
	for rows.Next() {
		p, err := scanPolicy(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *SQLStore) FindPolicyForAction(ctx context.Context, tenantID string, policyID string, action string) (ApprovalPolicy, error) {
	if strings.TrimSpace(policyID) != "" {
		return s.GetPolicy(ctx, tenantID, policyID)
	}
	policies, err := s.ListPolicies(ctx, tenantID, "", "active")
	if err != nil {
		return ApprovalPolicy{}, err
	}
	act := normalizeAction(action)
	for _, p := range policies {
		for _, t := range p.TriggerActions {
			if actionMatches(t, act) {
				return p, nil
			}
		}
	}
	return ApprovalPolicy{}, errNotFound
}

func (s *SQLStore) CreateApprovalRequest(ctx context.Context, req ApprovalRequest, tokens []ApprovalToken) error {
	targetDetails, _ := json.Marshal(req.TargetDetails)
	callbackPayload, _ := json.Marshal(req.CallbackPayload)
	return s.withTx(ctx, req.TenantID, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `
INSERT INTO approval_requests (
    id, tenant_id, policy_id, action, target_type, target_id, target_details, requester_id, requester_email, requester_ip,
    status, required_approvals, current_approvals, current_denials, created_at, expires_at, resolved_at, retain_until,
    callback_service, callback_action, callback_payload
) VALUES (
    $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,CURRENT_TIMESTAMP,$15,$16,$17,$18,$19,$20
)
`, req.ID, req.TenantID, req.PolicyID, req.Action, req.TargetType, req.TargetID, targetDetails, req.RequesterID, nullable(req.RequesterEmail),
			nullable(req.RequesterIP), req.Status, req.RequiredApprovals, req.CurrentApprovals, req.CurrentDenials, req.ExpiresAt,
			nullableTime(req.ResolvedAt), nullableTime(req.RetainUntil), req.CallbackService, req.CallbackAction, callbackPayload)
		if err != nil {
			return err
		}
		for _, t := range tokens {
			_, err := tx.ExecContext(ctx, `
INSERT INTO approval_tokens (id, request_id, approver_email, token_hash, action, used, expires_at, created_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,CURRENT_TIMESTAMP)
`, t.ID, t.RequestID, t.ApproverEmail, t.TokenHash, t.Action, false, t.ExpiresAt)
			if err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *SQLStore) GetApprovalRequest(ctx context.Context, tenantID string, requestID string) (ApprovalRequest, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT id, tenant_id, policy_id, action, target_type, target_id, target_details, requester_id, COALESCE(requester_email,''),
       COALESCE(CAST(requester_ip AS TEXT),''), status, required_approvals, current_approvals, current_denials, created_at, expires_at,
       resolved_at, retain_until, callback_service, callback_action, callback_payload
FROM approval_requests
WHERE tenant_id=$1 AND id=$2
`, tenantID, requestID)
	req, err := scanRequest(row)
	if errors.Is(err, sql.ErrNoRows) {
		return ApprovalRequest{}, errNotFound
	}
	return req, err
}

func (s *SQLStore) ListApprovalRequests(ctx context.Context, tenantID string, status string, targetType string, targetID string) ([]ApprovalRequest, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT id, tenant_id, policy_id, action, target_type, target_id, target_details, requester_id, COALESCE(requester_email,''),
       COALESCE(CAST(requester_ip AS TEXT),''), status, required_approvals, current_approvals, current_denials, created_at, expires_at,
       resolved_at, retain_until, callback_service, callback_action, callback_payload
FROM approval_requests
WHERE tenant_id=$1
  AND ($2='' OR status=$2)
  AND ($3='' OR target_type=$3)
  AND ($4='' OR target_id=$4)
ORDER BY created_at DESC
`, tenantID, strings.TrimSpace(status), strings.TrimSpace(targetType), strings.TrimSpace(targetID))
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	var out []ApprovalRequest
	for rows.Next() {
		r, err := scanRequest(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *SQLStore) ListApprovalVotes(ctx context.Context, tenantID string, requestID string) ([]ApprovalVote, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT id, request_id, tenant_id, approver_id, approver_email, vote, vote_method, COALESCE(comment,''), token_hash, voted_at, COALESCE(CAST(ip_address AS TEXT),'')
FROM approval_votes
WHERE tenant_id=$1 AND request_id=$2
ORDER BY voted_at ASC
`, tenantID, requestID)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	var out []ApprovalVote
	for rows.Next() {
		v, err := scanVote(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *SQLStore) CancelApprovalRequest(ctx context.Context, tenantID string, requestID string, requesterID string) error {
	res, err := s.db.SQL().ExecContext(ctx, `
UPDATE approval_requests
SET status='cancelled', resolved_at=CURRENT_TIMESTAMP, retain_until=CURRENT_TIMESTAMP
WHERE tenant_id=$1 AND id=$2 AND requester_id=$3 AND status='pending'
`, tenantID, requestID, requesterID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errNotFound
	}
	return nil
}

func (s *SQLStore) ListPendingByApprover(ctx context.Context, tenantID string, approverEmail string) ([]ApprovalRequest, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT DISTINCT r.id, r.tenant_id, r.policy_id, r.action, r.target_type, r.target_id, r.target_details, r.requester_id, COALESCE(r.requester_email,''),
       COALESCE(CAST(r.requester_ip AS TEXT),''), r.status, r.required_approvals, r.current_approvals, r.current_denials, r.created_at, r.expires_at,
       r.resolved_at, r.retain_until, r.callback_service, r.callback_action, r.callback_payload
FROM approval_requests r
JOIN approval_tokens t ON t.request_id = r.id
WHERE r.tenant_id=$1 AND r.status='pending' AND t.approver_email=$2 AND t.used=false AND t.expires_at > CURRENT_TIMESTAMP
ORDER BY r.created_at DESC
`, tenantID, strings.TrimSpace(strings.ToLower(approverEmail)))
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	var out []ApprovalRequest
	for rows.Next() {
		r, err := scanRequest(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *SQLStore) CountPendingByApprover(ctx context.Context, tenantID string, approverEmail string) (int, error) {
	var n int
	err := s.db.SQL().QueryRowContext(ctx, `
SELECT COUNT(DISTINCT r.id)
FROM approval_requests r
JOIN approval_tokens t ON t.request_id = r.id
WHERE r.tenant_id=$1 AND r.status='pending' AND t.approver_email=$2 AND t.used=false AND t.expires_at > CURRENT_TIMESTAMP
`, tenantID, strings.TrimSpace(strings.ToLower(approverEmail))).Scan(&n)
	return n, err
}

func (s *SQLStore) ConsumeToken(ctx context.Context, requestID string, tokenRaw string, expectedAction string) (ApprovalToken, error) {
	hash := sha256.Sum256([]byte(tokenRaw))
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT id, request_id, approver_email, token_hash, action, used, expires_at, created_at
FROM approval_tokens
WHERE request_id=$1 AND token_hash=$2
ORDER BY created_at DESC
LIMIT 1
`, requestID, hash[:])
	tok, err := scanToken(row)
	if errors.Is(err, sql.ErrNoRows) {
		return ApprovalToken{}, errNotFound
	}
	if err != nil {
		return ApprovalToken{}, err
	}
	if tok.Used || tok.ExpiresAt.Before(time.Now().UTC()) {
		return ApprovalToken{}, errors.New("token expired or already used")
	}
	if expectedAction != "" && !strings.EqualFold(tok.Action, expectedAction) {
		return ApprovalToken{}, errors.New("token action mismatch")
	}
	return tok, nil
}

func (s *SQLStore) ApplyVote(ctx context.Context, req ApprovalRequest, policy ApprovalPolicy, vote ApprovalVote) (ApprovalRequest, error) {
	returnReq := ApprovalRequest{}
	err := s.withTx(ctx, req.TenantID, func(tx *sql.Tx) error {
		var cur ApprovalRequest
		row := tx.QueryRowContext(ctx, `
SELECT id, tenant_id, policy_id, action, target_type, target_id, target_details, requester_id, COALESCE(requester_email,''),
       COALESCE(CAST(requester_ip AS TEXT),''), status, required_approvals, current_approvals, current_denials, created_at, expires_at,
       resolved_at, retain_until, callback_service, callback_action, callback_payload
FROM approval_requests
WHERE tenant_id=$1 AND id=$2
`, req.TenantID, req.ID)
		var err error
		cur, err = scanRequest(row)
		if err != nil {
			return err
		}
		if !strings.EqualFold(cur.Status, "pending") {
			return errors.New("request is not pending")
		}
		if cur.ExpiresAt.Before(time.Now().UTC()) {
			return errors.New("request expired")
		}

		var existing int
		if err := tx.QueryRowContext(ctx, `
SELECT COUNT(1) FROM approval_votes
WHERE tenant_id=$1 AND request_id=$2 AND approver_email=$3
`, req.TenantID, req.ID, strings.ToLower(strings.TrimSpace(vote.ApproverEmail))).Scan(&existing); err != nil {
			return err
		}
		if existing > 0 {
			return errors.New("approver already voted")
		}

		_, err = tx.ExecContext(ctx, `
INSERT INTO approval_votes (id, request_id, tenant_id, approver_id, approver_email, vote, vote_method, comment, token_hash, voted_at, ip_address)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,CURRENT_TIMESTAMP,$10)
`, vote.ID, vote.RequestID, vote.TenantID, vote.ApproverID, strings.ToLower(strings.TrimSpace(vote.ApproverEmail)),
			vote.Vote, vote.VoteMethod, nullable(vote.Comment), vote.TokenHash, nullable(vote.IPAddress))
		if err != nil {
			return err
		}

		_, err = tx.ExecContext(ctx, `
UPDATE approval_tokens SET used=true WHERE request_id=$1 AND token_hash=$2
`, req.ID, vote.TokenHash)
		if err != nil {
			return err
		}

		nextApprovals := cur.CurrentApprovals
		nextDenials := cur.CurrentDenials
		if strings.EqualFold(vote.Vote, "approved") {
			nextApprovals++
		} else {
			nextDenials++
		}
		totalApprovers := 0
		if err := tx.QueryRowContext(ctx, `
SELECT COUNT(DISTINCT approver_email)
FROM approval_tokens
WHERE request_id=$1 AND action='approve'
`, req.ID).Scan(&totalApprovers); err != nil {
			return err
		}
		if totalApprovers < 1 {
			totalApprovers = policy.TotalApprovers
		}
		if totalApprovers < 1 {
			totalApprovers = 1
		}
		requiredApprovals := cur.RequiredApprovals
		if requiredApprovals < 1 {
			requiredApprovals = 1
		}
		if requiredApprovals > totalApprovers {
			requiredApprovals = totalApprovers
		}

		nextStatus := "pending"
		switch normalizeQuorumMode(policy.QuorumMode) {
		case "and":
			if nextDenials > 0 {
				nextStatus = "denied"
			} else if nextApprovals >= totalApprovers {
				nextStatus = "approved"
			}
		case "or":
			if nextApprovals >= 1 {
				nextStatus = "approved"
			} else if nextDenials >= totalApprovers {
				nextStatus = "denied"
			}
		default:
			if nextApprovals >= requiredApprovals {
				nextStatus = "approved"
			} else {
				denyThreshold := totalApprovers - requiredApprovals + 1
				if denyThreshold < 1 {
					denyThreshold = 1
				}
				if nextDenials >= denyThreshold {
					nextStatus = "denied"
				}
			}
		}

		var resolvedAt interface{}
		var retainUntil interface{}
		if nextStatus != "pending" {
			now := time.Now().UTC()
			resolvedAt = now
			retentionDays := policy.RetentionDays
			if retentionDays <= 0 {
				retentionDays = 90
			}
			retainUntil = now.Add(time.Duration(retentionDays) * 24 * time.Hour)
		}
		_, err = tx.ExecContext(ctx, `
UPDATE approval_requests
SET current_approvals=$1, current_denials=$2, status=$3, resolved_at=$4, retain_until=$5
WHERE tenant_id=$6 AND id=$7
`, nextApprovals, nextDenials, nextStatus, resolvedAt, retainUntil, req.TenantID, req.ID)
		if err != nil {
			return err
		}
		row = tx.QueryRowContext(ctx, `
SELECT id, tenant_id, policy_id, action, target_type, target_id, target_details, requester_id, COALESCE(requester_email,''),
       COALESCE(CAST(requester_ip AS TEXT),''), status, required_approvals, current_approvals, current_denials, created_at, expires_at,
       resolved_at, retain_until, callback_service, callback_action, callback_payload
FROM approval_requests
WHERE tenant_id=$1 AND id=$2
`, req.TenantID, req.ID)
		returnReq, err = scanRequest(row)
		return err
	})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ApprovalRequest{}, errNotFound
		}
		return ApprovalRequest{}, err
	}
	return returnReq, nil
}

func (s *SQLStore) ExpirePendingRequests(ctx context.Context, now time.Time) ([]ApprovalRequest, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT id, tenant_id, policy_id, action, target_type, target_id, target_details, requester_id, COALESCE(requester_email,''),
       COALESCE(CAST(requester_ip AS TEXT),''), status, required_approvals, current_approvals, current_denials, created_at, expires_at,
       resolved_at, retain_until, callback_service, callback_action, callback_payload
FROM approval_requests
WHERE status='pending' AND expires_at <= $1
`, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	var expired []ApprovalRequest
	for rows.Next() {
		r, err := scanRequest(rows)
		if err != nil {
			return nil, err
		}
		expired = append(expired, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for _, r := range expired {
		_, _ = s.db.SQL().ExecContext(ctx, `
UPDATE approval_requests
SET status='expired', resolved_at=CURRENT_TIMESTAMP, retain_until=CURRENT_TIMESTAMP
WHERE tenant_id=$1 AND id=$2 AND status='pending'
`, r.TenantID, r.ID)
	}
	return expired, nil
}

func (s *SQLStore) GetSettings(ctx context.Context, tenantID string) (GovernanceSettings, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT tenant_id, approval_expiry_minutes, expiry_check_interval_seconds, COALESCE(approval_delivery_mode,'notify'),
       COALESCE(smtp_host,''), COALESCE(smtp_port,''), COALESCE(smtp_username,''), COALESCE(smtp_password,''),
       COALESCE(smtp_from,''), COALESCE(smtp_starttls,true), COALESCE(notify_dashboard,true), COALESCE(notify_email,true),
       COALESCE(notify_slack,false), COALESCE(notify_teams,false), COALESCE(slack_webhook_url,''), COALESCE(teams_webhook_url,''),
       COALESCE(delivery_webhook_timeout_seconds,5), COALESCE(challenge_response_enabled,false),
       COALESCE(updated_by,''), updated_at
FROM governance_settings
WHERE tenant_id=$1
`, tenantID)
	var out GovernanceSettings
	var updatedRaw interface{}
	err := row.Scan(
		&out.TenantID,
		&out.ApprovalExpiryMinutes,
		&out.ExpiryCheckIntervalSeconds,
		&out.ApprovalDeliveryMode,
		&out.SMTPHost,
		&out.SMTPPort,
		&out.SMTPUsername,
		&out.SMTPPassword,
		&out.SMTPFrom,
		&out.SMTPStartTLS,
		&out.NotifyDashboard,
		&out.NotifyEmail,
		&out.NotifySlack,
		&out.NotifyTeams,
		&out.SlackWebhookURL,
		&out.TeamsWebhookURL,
		&out.DeliveryWebhookTimeoutSec,
		&out.ChallengeResponseEnabled,
		&out.UpdatedBy,
		&updatedRaw,
	)
	if errors.Is(err, sql.ErrNoRows) {
		// default fallback row when not configured
		return GovernanceSettings{
			TenantID:                   tenantID,
			ApprovalExpiryMinutes:      60,
			ExpiryCheckIntervalSeconds: 60,
			ApprovalDeliveryMode:       "notify",
			SMTPStartTLS:               true,
			NotifyDashboard:            true,
			NotifyEmail:                true,
			DeliveryWebhookTimeoutSec:  5,
			ChallengeResponseEnabled:   false,
			UpdatedBy:                  "system",
		}, nil
	}
	if err != nil {
		return GovernanceSettings{}, err
	}
	out.UpdatedAt = parseTimeValue(updatedRaw)
	if out.ApprovalExpiryMinutes <= 0 {
		out.ApprovalExpiryMinutes = 60
	}
	if out.ExpiryCheckIntervalSeconds <= 0 {
		out.ExpiryCheckIntervalSeconds = 60
	}
	return out, nil
}

func (s *SQLStore) UpsertSettings(ctx context.Context, settings GovernanceSettings) error {
	if settings.ApprovalExpiryMinutes <= 0 {
		settings.ApprovalExpiryMinutes = 60
	}
	if settings.ExpiryCheckIntervalSeconds <= 0 {
		settings.ExpiryCheckIntervalSeconds = 60
	}
	_, err := s.db.SQL().ExecContext(ctx, `
	INSERT INTO governance_settings (
	    tenant_id, approval_expiry_minutes, expiry_check_interval_seconds,
	    approval_delivery_mode, smtp_host, smtp_port, smtp_username, smtp_password, smtp_from, smtp_starttls,
	    notify_dashboard, notify_email, notify_slack, notify_teams, slack_webhook_url, teams_webhook_url,
	    delivery_webhook_timeout_seconds, challenge_response_enabled,
	    updated_by, updated_at
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,CURRENT_TIMESTAMP)
ON CONFLICT (tenant_id) DO UPDATE
SET approval_expiry_minutes=EXCLUDED.approval_expiry_minutes,
    expiry_check_interval_seconds=EXCLUDED.expiry_check_interval_seconds,
    approval_delivery_mode=EXCLUDED.approval_delivery_mode,
    smtp_host=EXCLUDED.smtp_host,
    smtp_port=EXCLUDED.smtp_port,
    smtp_username=EXCLUDED.smtp_username,
    smtp_password=EXCLUDED.smtp_password,
    smtp_from=EXCLUDED.smtp_from,
    smtp_starttls=EXCLUDED.smtp_starttls,
    notify_dashboard=EXCLUDED.notify_dashboard,
    notify_email=EXCLUDED.notify_email,
    notify_slack=EXCLUDED.notify_slack,
    notify_teams=EXCLUDED.notify_teams,
    slack_webhook_url=EXCLUDED.slack_webhook_url,
    teams_webhook_url=EXCLUDED.teams_webhook_url,
    delivery_webhook_timeout_seconds=EXCLUDED.delivery_webhook_timeout_seconds,
    challenge_response_enabled=EXCLUDED.challenge_response_enabled,
    updated_by=EXCLUDED.updated_by,
    updated_at=CURRENT_TIMESTAMP
`, settings.TenantID, settings.ApprovalExpiryMinutes, settings.ExpiryCheckIntervalSeconds,
		settings.ApprovalDeliveryMode, nullable(settings.SMTPHost), nullable(settings.SMTPPort), nullable(settings.SMTPUsername),
		nullable(settings.SMTPPassword), nullable(settings.SMTPFrom), settings.SMTPStartTLS,
		settings.NotifyDashboard, settings.NotifyEmail, settings.NotifySlack, settings.NotifyTeams,
		nullable(settings.SlackWebhookURL), nullable(settings.TeamsWebhookURL), settings.DeliveryWebhookTimeoutSec,
		settings.ChallengeResponseEnabled, nullable(settings.UpdatedBy))
	return err
}

func (s *SQLStore) GetSystemState(ctx context.Context, tenantID string) (GovernanceSystemState, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT tenant_id, COALESCE(fips_mode,'disabled'), COALESCE(fips_mode_policy,'strict'),
       COALESCE(fips_crypto_library,'go-boringcrypto'), COALESCE(fips_library_validated,true),
       COALESCE(fips_tls_profile,'tls12_fips_suites'), COALESCE(fips_rng_mode,'ctr_drbg'),
       COALESCE(hsm_mode,'software'), COALESCE(cluster_mode,'standalone'),
       COALESCE(license_key,''), COALESCE(license_status,'inactive'),
       COALESCE(mgmt_ip,''), COALESCE(cluster_ip,''), COALESCE(dns_servers,''), COALESCE(ntp_servers,''),
       COALESCE(tls_mode,'internal_ca'), COALESCE(tls_cert_pem,''), COALESCE(tls_key_pem,''), COALESCE(tls_ca_bundle_pem,''),
       COALESCE(backup_schedule,'daily@02:00'), COALESCE(backup_target,'local'), COALESCE(backup_retention_days,30), COALESCE(backup_encrypted,true),
       COALESCE(proxy_endpoint,''), COALESCE(snmp_target,''),
       COALESCE(posture_force_quorum_destructive_ops,false),
       COALESCE(posture_require_step_up_auth,false),
       COALESCE(posture_pause_connector_sync,false),
       COALESCE(posture_guardrail_policy_required,false),
       COALESCE(updated_by,''), updated_at
FROM governance_system_state
WHERE tenant_id=$1
`, tenantID)
	var out GovernanceSystemState
	var updatedRaw interface{}
	err := row.Scan(
		&out.TenantID, &out.FIPSMode, &out.FIPSModePolicy,
		&out.FIPSCryptoLibrary, &out.FIPSLibraryValidated, &out.FIPSTLSProfile, &out.FIPSRNGMode,
		&out.HSMMode, &out.ClusterMode,
		&out.LicenseKey, &out.LicenseStatus,
		&out.MgmtIP, &out.ClusterIP, &out.DNSServers, &out.NTPServers,
		&out.TLSMode, &out.TLSCertPEM, &out.TLSKeyPEM, &out.TLSCABundlePEM,
		&out.BackupSchedule, &out.BackupTarget, &out.BackupRetentionDays, &out.BackupEncrypted,
		&out.ProxyEndpoint, &out.SNMPTarget,
		&out.PostureForceQuorumDestructiveOps,
		&out.PostureRequireStepUpAuth,
		&out.PosturePauseConnectorSync,
		&out.PostureGuardrailPolicyRequired,
		&out.UpdatedBy, &updatedRaw,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return GovernanceSystemState{
			TenantID:                         tenantID,
			FIPSMode:                         "disabled",
			FIPSModePolicy:                   "strict",
			FIPSCryptoLibrary:                "go-boringcrypto",
			FIPSLibraryValidated:             true,
			FIPSTLSProfile:                   "tls12_fips_suites",
			FIPSRNGMode:                      "ctr_drbg",
			FIPSEntropySource:                "os-csprng",
			FIPSEntropyHealth:                "unknown",
			HSMMode:                          "software",
			ClusterMode:                      "standalone",
			LicenseStatus:                    "inactive",
			TLSMode:                          "internal_ca",
			BackupSchedule:                   "daily@02:00",
			BackupTarget:                     "local",
			BackupRetentionDays:              30,
			BackupEncrypted:                  true,
			PostureForceQuorumDestructiveOps: false,
			PostureRequireStepUpAuth:         false,
			PosturePauseConnectorSync:        false,
			PostureGuardrailPolicyRequired:   false,
			UpdatedBy:                        "system",
		}, nil
	}
	if err != nil {
		return GovernanceSystemState{}, err
	}
	out.UpdatedAt = parseTimeValue(updatedRaw)
	return out, nil
}

func (s *SQLStore) UpsertSystemState(ctx context.Context, state GovernanceSystemState) error {
	if state.BackupRetentionDays <= 0 {
		state.BackupRetentionDays = 30
	}
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO governance_system_state (
    tenant_id, fips_mode, fips_mode_policy, fips_crypto_library, fips_library_validated, fips_tls_profile, fips_rng_mode,
    hsm_mode, cluster_mode, license_key, license_status,
    mgmt_ip, cluster_ip, dns_servers, ntp_servers,
    tls_mode, tls_cert_pem, tls_key_pem, tls_ca_bundle_pem,
    backup_schedule, backup_target, backup_retention_days, backup_encrypted,
    proxy_endpoint, snmp_target,
    posture_force_quorum_destructive_ops, posture_require_step_up_auth, posture_pause_connector_sync, posture_guardrail_policy_required,
    updated_by, updated_at
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,$30,CURRENT_TIMESTAMP)
ON CONFLICT (tenant_id) DO UPDATE
SET fips_mode=EXCLUDED.fips_mode,
    fips_mode_policy=EXCLUDED.fips_mode_policy,
    fips_crypto_library=EXCLUDED.fips_crypto_library,
    fips_library_validated=EXCLUDED.fips_library_validated,
    fips_tls_profile=EXCLUDED.fips_tls_profile,
    fips_rng_mode=EXCLUDED.fips_rng_mode,
    hsm_mode=EXCLUDED.hsm_mode,
    cluster_mode=EXCLUDED.cluster_mode,
    license_key=EXCLUDED.license_key,
    license_status=EXCLUDED.license_status,
    mgmt_ip=EXCLUDED.mgmt_ip,
    cluster_ip=EXCLUDED.cluster_ip,
    dns_servers=EXCLUDED.dns_servers,
    ntp_servers=EXCLUDED.ntp_servers,
    tls_mode=EXCLUDED.tls_mode,
    tls_cert_pem=EXCLUDED.tls_cert_pem,
    tls_key_pem=EXCLUDED.tls_key_pem,
    tls_ca_bundle_pem=EXCLUDED.tls_ca_bundle_pem,
    backup_schedule=EXCLUDED.backup_schedule,
    backup_target=EXCLUDED.backup_target,
    backup_retention_days=EXCLUDED.backup_retention_days,
    backup_encrypted=EXCLUDED.backup_encrypted,
    proxy_endpoint=EXCLUDED.proxy_endpoint,
    snmp_target=EXCLUDED.snmp_target,
    posture_force_quorum_destructive_ops=EXCLUDED.posture_force_quorum_destructive_ops,
    posture_require_step_up_auth=EXCLUDED.posture_require_step_up_auth,
    posture_pause_connector_sync=EXCLUDED.posture_pause_connector_sync,
    posture_guardrail_policy_required=EXCLUDED.posture_guardrail_policy_required,
    updated_by=EXCLUDED.updated_by,
    updated_at=CURRENT_TIMESTAMP
`, state.TenantID, nullable(state.FIPSMode), nullable(state.FIPSModePolicy),
		nullable(state.FIPSCryptoLibrary), state.FIPSLibraryValidated, nullable(state.FIPSTLSProfile), nullable(state.FIPSRNGMode),
		nullable(state.HSMMode), nullable(state.ClusterMode),
		nullable(state.LicenseKey), nullable(state.LicenseStatus),
		nullable(state.MgmtIP), nullable(state.ClusterIP), nullable(state.DNSServers), nullable(state.NTPServers),
		nullable(state.TLSMode), nullable(state.TLSCertPEM), nullable(state.TLSKeyPEM), nullable(state.TLSCABundlePEM),
		nullable(state.BackupSchedule), nullable(state.BackupTarget), state.BackupRetentionDays, state.BackupEncrypted,
		nullable(state.ProxyEndpoint), nullable(state.SNMPTarget),
		state.PostureForceQuorumDestructiveOps, state.PostureRequireStepUpAuth, state.PosturePauseConnectorSync, state.PostureGuardrailPolicyRequired,
		nullable(state.UpdatedBy))
	return err
}

func (s *SQLStore) withTx(ctx context.Context, tenantID string, fn func(tx *sql.Tx) error) error {
	tx, err := s.db.SQL().BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	_, _ = tx.ExecContext(ctx, "SELECT set_config('app.tenant_id', $1, true)", tenantID)
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit()
}

func scanPolicy(scanner interface {
	Scan(dest ...interface{}) error
}) (ApprovalPolicy, error) {
	var p ApprovalPolicy
	var triggerRaw []byte
	var rolesRaw []byte
	var usersRaw []byte
	var escalationRaw []byte
	var channelsRaw []byte
	var createdRaw interface{}
	err := scanner.Scan(
		&p.ID, &p.TenantID, &p.Name, &p.Description, &p.Scope, &triggerRaw, &p.RequiredApprovals, &p.TotalApprovers, &p.QuorumMode,
		&rolesRaw, &usersRaw, &p.TimeoutHours, &p.EscalationHours, &escalationRaw, &p.RetentionDays, &channelsRaw, &p.Status, &createdRaw,
	)
	if err != nil {
		return ApprovalPolicy{}, err
	}
	_ = json.Unmarshal(triggerRaw, &p.TriggerActions)
	_ = json.Unmarshal(rolesRaw, &p.ApproverRoles)
	_ = json.Unmarshal(usersRaw, &p.ApproverUsers)
	_ = json.Unmarshal(escalationRaw, &p.EscalationTo)
	_ = json.Unmarshal(channelsRaw, &p.NotificationChannels)
	p.CreatedAt = parseTimeValue(createdRaw)
	return p, nil
}

func scanRequest(scanner interface {
	Scan(dest ...interface{}) error
}) (ApprovalRequest, error) {
	var r ApprovalRequest
	var detailsRaw []byte
	var payloadRaw []byte
	var createdRaw, expiresRaw, resolvedRaw, retainRaw interface{}
	err := scanner.Scan(
		&r.ID, &r.TenantID, &r.PolicyID, &r.Action, &r.TargetType, &r.TargetID, &detailsRaw, &r.RequesterID, &r.RequesterEmail,
		&r.RequesterIP, &r.Status, &r.RequiredApprovals, &r.CurrentApprovals, &r.CurrentDenials, &createdRaw, &expiresRaw, &resolvedRaw, &retainRaw,
		&r.CallbackService, &r.CallbackAction, &payloadRaw,
	)
	if err != nil {
		return ApprovalRequest{}, err
	}
	_ = json.Unmarshal(detailsRaw, &r.TargetDetails)
	_ = json.Unmarshal(payloadRaw, &r.CallbackPayload)
	if r.TargetDetails == nil {
		r.TargetDetails = map[string]interface{}{}
	}
	if r.CallbackPayload == nil {
		r.CallbackPayload = map[string]interface{}{}
	}
	r.CreatedAt = parseTimeValue(createdRaw)
	r.ExpiresAt = parseTimeValue(expiresRaw)
	r.ResolvedAt = parseTimeValue(resolvedRaw)
	r.RetainUntil = parseTimeValue(retainRaw)
	return r, nil
}

func scanVote(scanner interface {
	Scan(dest ...interface{}) error
}) (ApprovalVote, error) {
	var v ApprovalVote
	var votedRaw interface{}
	err := scanner.Scan(&v.ID, &v.RequestID, &v.TenantID, &v.ApproverID, &v.ApproverEmail, &v.Vote, &v.VoteMethod, &v.Comment, &v.TokenHash, &votedRaw, &v.IPAddress)
	if err != nil {
		return ApprovalVote{}, err
	}
	v.VotedAt = parseTimeValue(votedRaw)
	return v, nil
}

func scanToken(scanner interface {
	Scan(dest ...interface{}) error
}) (ApprovalToken, error) {
	var t ApprovalToken
	var expiresRaw, createdRaw interface{}
	err := scanner.Scan(&t.ID, &t.RequestID, &t.ApproverEmail, &t.TokenHash, &t.Action, &t.Used, &expiresRaw, &createdRaw)
	if err != nil {
		return ApprovalToken{}, err
	}
	t.ExpiresAt = parseTimeValue(expiresRaw)
	t.CreatedAt = parseTimeValue(createdRaw)
	return t, nil
}

func normalizeAction(raw string) string {
	return strings.ReplaceAll(strings.ToLower(strings.TrimSpace(raw)), "_", "-")
}

func actionMatches(pattern string, action string) bool {
	p := normalizeAction(pattern)
	a := normalizeAction(action)
	if p == "" || a == "" {
		return false
	}
	if p == "*" {
		return true
	}
	if strings.HasSuffix(p, ".*") {
		prefix := strings.TrimSuffix(p, "*")
		return strings.HasPrefix(a, prefix)
	}
	return p == a
}

func normalizeQuorumMode(raw string) string {
	mode := strings.ToLower(strings.TrimSpace(raw))
	switch mode {
	case "and", "all":
		return "and"
	case "or", "any":
		return "or"
	case "", "threshold", "m-of-n", "mofn":
		return "threshold"
	default:
		return "threshold"
	}
}

func nullable(v string) interface{} {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	return strings.TrimSpace(v)
}

func nullableInt(v int) interface{} {
	if v == 0 {
		return nil
	}
	return v
}

func nullableTime(v time.Time) interface{} {
	if v.IsZero() {
		return nil
	}
	return v
}

func nullableJSON(v []byte) interface{} {
	if len(v) == 0 {
		return nil
	}
	return v
}

func parseTimeValue(v interface{}) time.Time {
	switch x := v.(type) {
	case nil:
		return time.Time{}
	case time.Time:
		return x
	case string:
		return parseTimeString(x)
	case []byte:
		return parseTimeString(string(x))
	default:
		return time.Time{}
	}
}

func parseTimeString(v string) time.Time {
	v = strings.TrimSpace(v)
	if v == "" {
		return time.Time{}
	}
	layouts := []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02 15:04:05.999999999 -0700 MST",
		"2006-01-02 15:04:05 -0700 MST",
		"2006-01-02 15:04:05.999999999-07:00",
		"2006-01-02 15:04:05-07:00",
		"2006-01-02 15:04:05.999999999",
		"2006-01-02 15:04:05",
	}
	for _, layout := range layouts {
		if ts, err := time.Parse(layout, v); err == nil {
			return ts.UTC()
		}
	}
	return time.Time{}
}

func sha256Hex(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}
