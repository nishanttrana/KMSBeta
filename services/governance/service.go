package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"
)

type EventPublisher interface {
	Publish(ctx context.Context, subject string, payload []byte) error
}

type Service struct {
	store    Store
	events   EventPublisher
	email    EmailSender
	callback CallbackExecutor
	baseURL  string
}

func NewService(store Store, events EventPublisher, email EmailSender, callback CallbackExecutor, baseURL string) *Service {
	if callback == nil {
		callback = NoopCallbackExecutor{}
	}
	return &Service{
		store:    store,
		events:   events,
		email:    email,
		callback: callback,
		baseURL:  strings.TrimSpace(baseURL),
	}
}

func (s *Service) CreatePolicy(ctx context.Context, p ApprovalPolicy) (ApprovalPolicy, error) {
	p = normalizePolicy(p)
	if err := validatePolicy(p); err != nil {
		return ApprovalPolicy{}, err
	}
	if p.ID == "" {
		p.ID = newID("apol")
	}
	if err := s.store.CreatePolicy(ctx, p); err != nil {
		return ApprovalPolicy{}, err
	}
	_ = s.publishAudit(ctx, "audit.governance.policy_created", p.TenantID, map[string]interface{}{"policy_id": p.ID})
	return s.store.GetPolicy(ctx, p.TenantID, p.ID)
}

func (s *Service) UpdatePolicy(ctx context.Context, p ApprovalPolicy) (ApprovalPolicy, error) {
	p = normalizePolicy(p)
	if err := validatePolicy(p); err != nil {
		return ApprovalPolicy{}, err
	}
	if p.ID == "" {
		return ApprovalPolicy{}, errors.New("policy id is required")
	}
	if err := s.store.UpdatePolicy(ctx, p); err != nil {
		return ApprovalPolicy{}, err
	}
	_ = s.publishAudit(ctx, "audit.governance.policy_updated", p.TenantID, map[string]interface{}{"policy_id": p.ID})
	return s.store.GetPolicy(ctx, p.TenantID, p.ID)
}

func (s *Service) DeletePolicy(ctx context.Context, tenantID string, policyID string) error {
	if err := s.store.DeletePolicy(ctx, tenantID, policyID); err != nil {
		return err
	}
	_ = s.publishAudit(ctx, "audit.governance.policy_deleted", tenantID, map[string]interface{}{"policy_id": policyID})
	return nil
}

func (s *Service) ListPolicies(ctx context.Context, tenantID string, scope string, status string) ([]ApprovalPolicy, error) {
	return s.store.ListPolicies(ctx, tenantID, scope, status)
}

func (s *Service) CreateApprovalRequest(ctx context.Context, in CreateApprovalRequestInput) (ApprovalRequest, error) {
	in = normalizeCreateInput(in)
	if err := validateCreateInput(in); err != nil {
		return ApprovalRequest{}, err
	}
	policy, err := s.store.FindPolicyForAction(ctx, in.TenantID, in.PolicyID, in.Action)
	if err != nil {
		return ApprovalRequest{}, err
	}
	settings, err := s.GetSettings(ctx, in.TenantID)
	if err != nil {
		return ApprovalRequest{}, err
	}
	expiryMinutes := clamp(settings.ApprovalExpiryMinutes, 1, 1440)
	approvers := resolveApprovers(policy, in.TargetDetails)
	if len(approvers) == 0 {
		return ApprovalRequest{}, errors.New("no approvers configured for policy")
	}
	requiredApprovals := effectiveRequiredApprovals(policy, len(approvers))

	req := ApprovalRequest{
		ID:                newID("apr"),
		TenantID:          in.TenantID,
		PolicyID:          policy.ID,
		Action:            strings.ToLower(strings.TrimSpace(in.Action)),
		TargetType:        strings.ToLower(strings.TrimSpace(in.TargetType)),
		TargetID:          in.TargetID,
		TargetDetails:     in.TargetDetails,
		RequesterID:       in.RequesterID,
		RequesterEmail:    in.RequesterEmail,
		RequesterIP:       in.RequesterIP,
		Status:            "pending",
		RequiredApprovals: requiredApprovals,
		CurrentApprovals:  0,
		CurrentDenials:    0,
		ExpiresAt:         time.Now().UTC().Add(time.Duration(expiryMinutes) * time.Minute),
		CallbackService:   in.CallbackService,
		CallbackAction:    in.CallbackAction,
		CallbackPayload:   in.CallbackPayload,
	}

	tokens := make([]ApprovalToken, 0, len(approvers)*2)
	type pair struct {
		approve string
		deny    string
	}
	emailTokens := map[string]pair{}
	challengeCodes := map[string]string{}
	for _, email := range approvers {
		approveRaw, approveHash, err := generateToken()
		if err != nil {
			return ApprovalRequest{}, err
		}
		denyRaw, denyHash, err := generateToken()
		if err != nil {
			return ApprovalRequest{}, err
		}
		emailTokens[email] = pair{approve: approveRaw, deny: denyRaw}
		tokens = append(tokens, ApprovalToken{
			ID:            newID("atok"),
			RequestID:     req.ID,
			ApproverEmail: email,
			TokenHash:     approveHash,
			Action:        "approve",
			ExpiresAt:     req.ExpiresAt,
		})
		tokens = append(tokens, ApprovalToken{
			ID:            newID("atok"),
			RequestID:     req.ID,
			ApproverEmail: email,
			TokenHash:     denyHash,
			Action:        "deny",
			ExpiresAt:     req.ExpiresAt,
		})
		if settings.ChallengeResponseEnabled {
			challengeRaw, challengeHash, err := generateChallengeCode()
			if err != nil {
				return ApprovalRequest{}, err
			}
			challengeCodes[email] = challengeRaw
			tokens = append(tokens, ApprovalToken{
				ID:            newID("atok"),
				RequestID:     req.ID,
				ApproverEmail: email,
				TokenHash:     challengeHash,
				Action:        "challenge",
				ExpiresAt:     req.ExpiresAt,
			})
		}
	}

	if err := s.store.CreateApprovalRequest(ctx, req, tokens); err != nil {
		return ApprovalRequest{}, err
	}
	_ = s.publishAudit(ctx, "audit.governance.request_created", req.TenantID, map[string]interface{}{
		"request_id": req.ID,
		"action":     req.Action,
	})

	for email, tok := range emailTokens {
		if !settings.NotifyEmail {
			continue
		}
		sender := s.email
		if sender == nil && strings.TrimSpace(settings.SMTPHost) != "" && strings.TrimSpace(settings.SMTPPort) != "" {
			sender = NewSMTPMailer(SMTPConfig{
				Host:     settings.SMTPHost,
				Port:     settings.SMTPPort,
				Username: settings.SMTPUsername,
				Password: settings.SMTPPassword,
				From:     settings.SMTPFrom,
				StartTLS: settings.SMTPStartTLS,
			})
		}
		if sender == nil {
			continue
		}
		body := buildApprovalEmailBody(s.baseURL, req, tok.approve, tok.deny, challengeCodes[email], settings.ChallengeResponseEnabled)
		subject := "[Vecta KMS] Approval Required: " + req.Action + " (" + req.TargetID + ")"
		if err := sender.Send(ctx, EmailMessage{To: email, Subject: subject, Body: body}); err == nil {
			_ = s.publishAudit(ctx, "audit.governance.email_sent", req.TenantID, map[string]interface{}{
				"request_id": req.ID,
				"to":         email,
			})
		}
	}
	return s.store.GetApprovalRequest(ctx, req.TenantID, req.ID)
}

func (s *Service) GetApprovalRequest(ctx context.Context, tenantID string, requestID string) (ApprovalRequestDetails, error) {
	req, err := s.store.GetApprovalRequest(ctx, tenantID, requestID)
	if err != nil {
		return ApprovalRequestDetails{}, err
	}
	votes, err := s.store.ListApprovalVotes(ctx, tenantID, requestID)
	if err != nil {
		return ApprovalRequestDetails{}, err
	}
	return ApprovalRequestDetails{Request: req, Votes: votes}, nil
}

func (s *Service) ListApprovalRequests(ctx context.Context, tenantID string, status string, targetType string, targetID string) ([]ApprovalRequest, error) {
	return s.store.ListApprovalRequests(ctx, tenantID, status, targetType, targetID)
}

func (s *Service) CancelApprovalRequest(ctx context.Context, tenantID string, requestID string, requesterID string) error {
	if err := s.store.CancelApprovalRequest(ctx, tenantID, requestID, requesterID); err != nil {
		return err
	}
	_ = s.publishAudit(ctx, "audit.governance.request_cancelled", tenantID, map[string]interface{}{"request_id": requestID})
	return nil
}

func (s *Service) Vote(ctx context.Context, in VoteInput) (ApprovalRequest, error) {
	in = normalizeVoteInput(in)
	if in.Vote != "approved" && in.Vote != "denied" {
		return ApprovalRequest{}, errors.New("vote must be approved or denied")
	}
	details, err := s.GetApprovalRequest(ctx, in.TenantID, in.RequestID)
	if err != nil {
		return ApprovalRequest{}, err
	}
	policy, err := s.store.GetPolicy(ctx, in.TenantID, details.Request.PolicyID)
	if err != nil {
		return ApprovalRequest{}, err
	}
	approverEmail := in.ApproverEmail
	approverID := in.ApproverID
	voteMethod := firstNonEmpty(in.VoteMethod, "email_link")
	var tokenHash []byte
	if in.Token != "" {
		expectedAction := "approve"
		if in.Vote == "denied" {
			expectedAction = "deny"
		}
		token, consumeErr := s.store.ConsumeToken(ctx, in.RequestID, in.Token, expectedAction)
		if consumeErr != nil {
			return ApprovalRequest{}, consumeErr
		}
		approverEmail = firstNonEmpty(in.ApproverEmail, token.ApproverEmail)
		approverID = firstNonEmpty(in.ApproverID, in.ApproverEmail, token.ApproverEmail)
		tokenHash = token.TokenHash
	} else {
		settings, err := s.GetSettings(ctx, in.TenantID)
		if err != nil {
			return ApprovalRequest{}, err
		}
		if settings.ChallengeResponseEnabled {
			if strings.TrimSpace(in.ChallengeCode) == "" {
				return ApprovalRequest{}, errors.New("challenge_code is required")
			}
			challengeToken, consumeErr := s.store.ConsumeToken(ctx, in.RequestID, in.ChallengeCode, "challenge")
			if consumeErr != nil {
				return ApprovalRequest{}, consumeErr
			}
			approverEmail = firstNonEmpty(in.ApproverEmail, challengeToken.ApproverEmail)
			approverID = firstNonEmpty(in.ApproverID, in.ApproverEmail, challengeToken.ApproverEmail)
			tokenHash = challengeToken.TokenHash
			voteMethod = firstNonEmpty(in.VoteMethod, "dashboard_challenge")
		} else {
			if approverEmail == "" {
				return ApprovalRequest{}, errors.New("token or approver_email is required")
			}
			allowed := resolveApprovers(policy, details.Request.TargetDetails)
			if len(allowed) > 0 && !containsIgnoreCase(allowed, approverEmail) {
				return ApprovalRequest{}, errors.New("approver_email is not allowed for this request")
			}
			approverID = firstNonEmpty(in.ApproverID, approverEmail)
			voteMethod = firstNonEmpty(in.VoteMethod, "dashboard")
		}
	}
	vote := ApprovalVote{
		ID:            newID("avt"),
		RequestID:     in.RequestID,
		TenantID:      in.TenantID,
		ApproverID:    approverID,
		ApproverEmail: approverEmail,
		Vote:          in.Vote,
		VoteMethod:    voteMethod,
		Comment:       in.Comment,
		TokenHash:     tokenHash,
		IPAddress:     in.IPAddress,
	}
	updated, err := s.store.ApplyVote(ctx, details.Request, policy, vote)
	if err != nil {
		return ApprovalRequest{}, err
	}

	if updated.Status == "approved" {
		if err := s.callback.Execute(ctx, updated); err == nil {
			_ = s.publishAudit(ctx, "audit.governance.callback_executed", updated.TenantID, map[string]interface{}{"request_id": updated.ID})
		}
		_ = s.publishAudit(ctx, "audit.governance.quorum_reached", updated.TenantID, map[string]interface{}{"request_id": updated.ID})
	}
	if updated.Status == "denied" {
		_ = s.publishAudit(ctx, "audit.governance.quorum_denied", updated.TenantID, map[string]interface{}{"request_id": updated.ID})
	}
	if strings.EqualFold(vote.Vote, "approved") {
		_ = s.publishAudit(ctx, "audit.governance.vote_approved", updated.TenantID, map[string]interface{}{"request_id": updated.ID})
	} else {
		_ = s.publishAudit(ctx, "audit.governance.vote_denied", updated.TenantID, map[string]interface{}{"request_id": updated.ID})
	}
	return updated, nil
}

func (s *Service) ListPendingByApprover(ctx context.Context, tenantID string, approverEmail string) ([]ApprovalRequest, error) {
	return s.store.ListPendingByApprover(ctx, tenantID, approverEmail)
}

func (s *Service) CountPendingByApprover(ctx context.Context, tenantID string, approverEmail string) (int, error) {
	return s.store.CountPendingByApprover(ctx, tenantID, approverEmail)
}

func (s *Service) CreateKeyApproval(ctx context.Context, in CreateKeyApprovalInput) (ApprovalRequest, error) {
	return s.CreateApprovalRequest(ctx, CreateApprovalRequestInput{
		TenantID:        in.TenantID,
		PolicyID:        in.PolicyID,
		Action:          "key." + strings.ToLower(strings.TrimSpace(in.Operation)),
		TargetType:      "key",
		TargetID:        in.KeyID,
		TargetDetails:   map[string]interface{}{"payload_hash": in.PayloadHash, "operation": in.Operation},
		RequesterID:     in.RequesterID,
		RequesterEmail:  in.RequesterEmail,
		RequesterIP:     in.RequesterIP,
		CallbackService: in.CallbackService,
		CallbackAction:  in.CallbackAction,
		CallbackPayload: in.CallbackPayload,
	})
}

func (s *Service) GetKeyApprovalStatus(ctx context.Context, tenantID string, requestID string) (ApprovalStatus, error) {
	req, err := s.store.GetApprovalRequest(ctx, tenantID, requestID)
	if err != nil {
		return ApprovalStatus{}, err
	}
	return ApprovalStatus{
		Status:           req.Status,
		CurrentApprovals: req.CurrentApprovals,
		CurrentDenials:   req.CurrentDenials,
		ExpiresAt:        req.ExpiresAt,
	}, nil
}

func (s *Service) GetSettings(ctx context.Context, tenantID string) (GovernanceSettings, error) {
	settings, err := s.store.GetSettings(ctx, tenantID)
	if err != nil {
		return GovernanceSettings{}, err
	}
	settings.ApprovalExpiryMinutes = clamp(settings.ApprovalExpiryMinutes, 1, 1440)
	settings.ExpiryCheckIntervalSeconds = clamp(settings.ExpiryCheckIntervalSeconds, 5, 3600)
	if strings.TrimSpace(settings.SMTPPort) == "" {
		settings.SMTPPort = "587"
	}
	if !settings.NotifyDashboard && !settings.NotifyEmail {
		settings.NotifyDashboard = true
		settings.NotifyEmail = true
	}
	return settings, nil
}

func (s *Service) UpdateSettings(ctx context.Context, settings GovernanceSettings) (GovernanceSettings, error) {
	settings.TenantID = strings.TrimSpace(settings.TenantID)
	if settings.TenantID == "" {
		return GovernanceSettings{}, errors.New("tenant_id is required")
	}
	settings.ApprovalExpiryMinutes = clamp(settings.ApprovalExpiryMinutes, 1, 1440)
	settings.ExpiryCheckIntervalSeconds = clamp(settings.ExpiryCheckIntervalSeconds, 5, 3600)
	if strings.TrimSpace(settings.SMTPPort) == "" {
		settings.SMTPPort = "587"
	}
	if !settings.SMTPStartTLS {
		settings.SMTPStartTLS = false
	} else {
		settings.SMTPStartTLS = true
	}
	if settings.UpdatedBy == "" {
		settings.UpdatedBy = "system"
	}
	if !settings.NotifyDashboard && !settings.NotifyEmail {
		settings.NotifyDashboard = true
		settings.NotifyEmail = true
	}
	if settings.ChallengeResponseEnabled && !settings.NotifyEmail {
		settings.NotifyEmail = true
	}
	if err := s.store.UpsertSettings(ctx, settings); err != nil {
		return GovernanceSettings{}, err
	}
	return s.GetSettings(ctx, settings.TenantID)
}

func (s *Service) TestSMTP(ctx context.Context, tenantID string, to string) error {
	settings, err := s.GetSettings(ctx, tenantID)
	if err != nil {
		return err
	}
	if strings.TrimSpace(settings.SMTPHost) == "" || strings.TrimSpace(settings.SMTPPort) == "" {
		return errors.New("smtp settings are not configured")
	}
	if strings.TrimSpace(to) == "" {
		return errors.New("recipient email is required")
	}
	sender := NewSMTPMailer(SMTPConfig{
		Host:     settings.SMTPHost,
		Port:     settings.SMTPPort,
		Username: settings.SMTPUsername,
		Password: settings.SMTPPassword,
		From:     settings.SMTPFrom,
		StartTLS: settings.SMTPStartTLS,
	})
	return sender.Send(ctx, EmailMessage{
		To:      to,
		Subject: "[Vecta KMS] SMTP configuration test",
		Body:    "SMTP connectivity test for governance approvals.",
	})
}

func (s *Service) GetSystemState(ctx context.Context, tenantID string) (GovernanceSystemState, error) {
	out, err := s.store.GetSystemState(ctx, tenantID)
	if err != nil {
		return GovernanceSystemState{}, err
	}
	return normalizeSystemState(out), nil
}

func (s *Service) UpdateSystemState(ctx context.Context, state GovernanceSystemState) (GovernanceSystemState, error) {
	state = normalizeSystemState(state)
	if state.TenantID == "" {
		return GovernanceSystemState{}, errors.New("tenant_id is required")
	}
	if state.UpdatedBy == "" {
		state.UpdatedBy = "system"
	}
	if state.LicenseKey != "" {
		state.LicenseStatus = "active"
	}
	if err := s.store.UpsertSystemState(ctx, state); err != nil {
		return GovernanceSystemState{}, err
	}
	_ = s.publishAudit(ctx, "audit.governance.system_state_updated", state.TenantID, map[string]interface{}{
		"fips_mode":      state.FIPSMode,
		"hsm_mode":       state.HSMMode,
		"cluster_mode":   state.ClusterMode,
		"license_status": state.LicenseStatus,
	})
	return s.GetSystemState(ctx, state.TenantID)
}

func (s *Service) SystemIntegrity(ctx context.Context, tenantID string) (SystemIntegrityStatus, error) {
	settings, err := s.GetSettings(ctx, tenantID)
	if err != nil {
		return SystemIntegrityStatus{}, err
	}
	sys, err := s.GetSystemState(ctx, tenantID)
	if err != nil {
		return SystemIntegrityStatus{}, err
	}
	checks := map[string]string{
		"smtp":       "not_configured",
		"fips":       sys.FIPSMode,
		"hsm":        sys.HSMMode,
		"license":    sys.LicenseStatus,
		"network":    "missing",
		"backup":     "missing",
		"proxy":      "not_configured",
		"snmp":       "not_configured",
		"cluster":    sys.ClusterMode,
		"tls":        sys.TLSMode,
		"governance": "ok",
	}

	if strings.TrimSpace(settings.SMTPHost) != "" && strings.TrimSpace(settings.SMTPPort) != "" {
		checks["smtp"] = "configured"
	}
	if strings.TrimSpace(sys.MgmtIP) != "" && strings.TrimSpace(sys.DNSServers) != "" && strings.TrimSpace(sys.NTPServers) != "" {
		checks["network"] = "configured"
	}
	if strings.TrimSpace(sys.BackupSchedule) != "" && strings.TrimSpace(sys.BackupTarget) != "" && sys.BackupRetentionDays > 0 {
		checks["backup"] = "configured"
	}
	if strings.TrimSpace(sys.ProxyEndpoint) != "" {
		checks["proxy"] = "configured"
	}
	if strings.TrimSpace(sys.SNMPTarget) != "" {
		checks["snmp"] = "configured"
	}
	if strings.TrimSpace(sys.LicenseKey) == "" {
		checks["license"] = "inactive"
	}

	status := "healthy"
	for _, value := range checks {
		if value == "missing" || value == "inactive" {
			status = "degraded"
			break
		}
	}

	return SystemIntegrityStatus{
		TenantID:  tenantID,
		Status:    status,
		Checks:    checks,
		Timestamp: time.Now().UTC(),
	}, nil
}

func (s *Service) ExpireWorkerTick(ctx context.Context) error {
	expired, err := s.store.ExpirePendingRequests(ctx, time.Now().UTC())
	if err != nil {
		return err
	}
	for _, req := range expired {
		_ = s.publishAudit(ctx, "audit.governance.request_expired", req.TenantID, map[string]interface{}{"request_id": req.ID})
	}
	return nil
}

func normalizeSystemState(in GovernanceSystemState) GovernanceSystemState {
	in.TenantID = strings.TrimSpace(in.TenantID)
	in.FIPSMode = strings.ToLower(strings.TrimSpace(in.FIPSMode))
	if in.FIPSMode == "" {
		in.FIPSMode = "disabled"
	}
	in.HSMMode = strings.ToLower(strings.TrimSpace(in.HSMMode))
	if in.HSMMode == "" {
		in.HSMMode = "software"
	}
	in.ClusterMode = strings.ToLower(strings.TrimSpace(in.ClusterMode))
	if in.ClusterMode == "" {
		in.ClusterMode = "standalone"
	}
	in.LicenseStatus = strings.ToLower(strings.TrimSpace(in.LicenseStatus))
	if in.LicenseStatus == "" {
		in.LicenseStatus = "inactive"
	}
	in.TLSMode = strings.ToLower(strings.TrimSpace(in.TLSMode))
	if in.TLSMode == "" {
		in.TLSMode = "internal_ca"
	}
	in.BackupSchedule = strings.TrimSpace(in.BackupSchedule)
	if in.BackupSchedule == "" {
		in.BackupSchedule = "daily@02:00"
	}
	in.BackupTarget = strings.TrimSpace(in.BackupTarget)
	if in.BackupTarget == "" {
		in.BackupTarget = "local"
	}
	if in.BackupRetentionDays <= 0 {
		in.BackupRetentionDays = 30
	}
	in.MgmtIP = strings.TrimSpace(in.MgmtIP)
	in.ClusterIP = strings.TrimSpace(in.ClusterIP)
	in.DNSServers = strings.TrimSpace(in.DNSServers)
	in.NTPServers = strings.TrimSpace(in.NTPServers)
	in.ProxyEndpoint = strings.TrimSpace(in.ProxyEndpoint)
	in.SNMPTarget = strings.TrimSpace(in.SNMPTarget)
	in.UpdatedBy = strings.TrimSpace(in.UpdatedBy)
	return in
}

func (s *Service) ExpiryCheckInterval(ctx context.Context, tenantID string) time.Duration {
	settings, err := s.GetSettings(ctx, tenantID)
	if err != nil {
		return 60 * time.Second
	}
	return time.Duration(settings.ExpiryCheckIntervalSeconds) * time.Second
}

func (s *Service) ApprovalPageHTML(ctx context.Context, tenantID string, requestID string, token string) (string, error) {
	req, err := s.store.GetApprovalRequest(ctx, tenantID, requestID)
	if err != nil {
		return "", err
	}
	if token == "" {
		return "", errors.New("token is required")
	}
	_ = s.publishAudit(ctx, "audit.governance.link_accessed", tenantID, map[string]interface{}{"request_id": requestID})
	return buildApprovalPage(req, token), nil
}

func (s *Service) publishAudit(ctx context.Context, subject string, tenantID string, data map[string]interface{}) error {
	if s.events == nil {
		return nil
	}
	raw, err := json.Marshal(map[string]interface{}{
		"tenant_id": tenantID,
		"timestamp": time.Now().UTC().Format(time.RFC3339Nano),
		"service":   "governance",
		"action":    subject,
		"result":    "success",
		"data":      data,
	})
	if err != nil {
		return err
	}
	return s.events.Publish(ctx, subject, raw)
}

func normalizePolicy(p ApprovalPolicy) ApprovalPolicy {
	p.TenantID = strings.TrimSpace(p.TenantID)
	p.Name = strings.TrimSpace(p.Name)
	p.Scope = strings.TrimSpace(strings.ToLower(p.Scope))
	p.Status = strings.TrimSpace(strings.ToLower(p.Status))
	if p.Status == "" {
		p.Status = "active"
	}
	if p.TimeoutHours <= 0 {
		p.TimeoutHours = 48
	}
	if p.RetentionDays <= 0 {
		p.RetentionDays = 90
	}
	if p.RequiredApprovals <= 0 {
		p.RequiredApprovals = 1
	}
	if p.TotalApprovers < p.RequiredApprovals {
		p.TotalApprovers = p.RequiredApprovals
	}
	if p.TotalApprovers < 1 {
		p.TotalApprovers = 1
	}
	p.QuorumMode = normalizeQuorumMode(p.QuorumMode)
	switch p.QuorumMode {
	case "and":
		p.RequiredApprovals = p.TotalApprovers
	case "or":
		p.RequiredApprovals = 1
	}
	if len(p.NotificationChannels) == 0 {
		p.NotificationChannels = []string{"email"}
	}
	for i := range p.TriggerActions {
		p.TriggerActions[i] = strings.ToLower(strings.TrimSpace(p.TriggerActions[i]))
	}
	for i := range p.ApproverUsers {
		p.ApproverUsers[i] = strings.ToLower(strings.TrimSpace(p.ApproverUsers[i]))
	}
	return p
}

func validatePolicy(p ApprovalPolicy) error {
	if p.TenantID == "" {
		return errors.New("tenant_id is required")
	}
	if p.Name == "" {
		return errors.New("name is required")
	}
	if p.Scope == "" {
		return errors.New("scope is required")
	}
	if len(p.TriggerActions) == 0 {
		return errors.New("trigger_actions are required")
	}
	mode := normalizeQuorumMode(p.QuorumMode)
	if mode != "and" && mode != "or" && mode != "threshold" {
		return errors.New("quorum_mode must be and/or/threshold")
	}
	if p.RequiredApprovals <= 0 || p.TotalApprovers <= 0 || p.RequiredApprovals > p.TotalApprovers {
		return errors.New("invalid required_approvals/total_approvers")
	}
	return nil
}

func normalizeCreateInput(in CreateApprovalRequestInput) CreateApprovalRequestInput {
	in.TenantID = strings.TrimSpace(in.TenantID)
	in.PolicyID = strings.TrimSpace(in.PolicyID)
	in.Action = strings.ToLower(strings.TrimSpace(in.Action))
	in.TargetType = strings.ToLower(strings.TrimSpace(in.TargetType))
	in.TargetID = strings.TrimSpace(in.TargetID)
	in.RequesterID = strings.TrimSpace(in.RequesterID)
	in.RequesterEmail = strings.ToLower(strings.TrimSpace(in.RequesterEmail))
	in.RequesterIP = strings.TrimSpace(in.RequesterIP)
	in.CallbackService = strings.TrimSpace(in.CallbackService)
	in.CallbackAction = strings.TrimSpace(in.CallbackAction)
	if in.TargetDetails == nil {
		in.TargetDetails = map[string]interface{}{}
	}
	if in.CallbackPayload == nil {
		in.CallbackPayload = map[string]interface{}{}
	}
	return in
}

func validateCreateInput(in CreateApprovalRequestInput) error {
	if in.TenantID == "" {
		return errors.New("tenant_id is required")
	}
	if in.Action == "" {
		return errors.New("action is required")
	}
	if in.TargetType == "" || in.TargetID == "" {
		return errors.New("target_type and target_id are required")
	}
	if in.RequesterID == "" {
		return errors.New("requester_id is required")
	}
	return nil
}

func normalizeVoteInput(in VoteInput) VoteInput {
	in.TenantID = strings.TrimSpace(in.TenantID)
	in.RequestID = strings.TrimSpace(in.RequestID)
	in.Vote = strings.ToLower(strings.TrimSpace(in.Vote))
	in.Token = strings.TrimSpace(in.Token)
	in.ChallengeCode = strings.TrimSpace(in.ChallengeCode)
	in.ApproverID = strings.TrimSpace(in.ApproverID)
	in.ApproverEmail = strings.ToLower(strings.TrimSpace(in.ApproverEmail))
	in.VoteMethod = strings.ToLower(strings.TrimSpace(in.VoteMethod))
	if in.VoteMethod == "" {
		in.VoteMethod = "email_link"
	}
	in.IPAddress = strings.TrimSpace(in.IPAddress)
	return in
}

func resolveApprovers(policy ApprovalPolicy, targetDetails map[string]interface{}) []string {
	seen := map[string]struct{}{}
	var out []string
	add := func(v string) {
		v = strings.ToLower(strings.TrimSpace(v))
		if v == "" {
			return
		}
		if _, ok := seen[v]; ok {
			return
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	for _, u := range policy.ApproverUsers {
		add(u)
	}
	if raw, ok := targetDetails["approver_emails"]; ok {
		switch arr := raw.(type) {
		case []interface{}:
			for _, it := range arr {
				if s, ok := it.(string); ok {
					add(s)
				}
			}
		case []string:
			for _, it := range arr {
				add(it)
			}
		}
	}
	return out
}

func effectiveRequiredApprovals(policy ApprovalPolicy, approverCount int) int {
	total := maxInt(1, approverCount)
	switch normalizeQuorumMode(policy.QuorumMode) {
	case "and":
		return total
	case "or":
		return 1
	default:
		required := policy.RequiredApprovals
		if required < 1 {
			required = 1
		}
		if required > total {
			required = total
		}
		return required
	}
}

func containsIgnoreCase(values []string, needle string) bool {
	needle = strings.ToLower(strings.TrimSpace(needle))
	for _, v := range values {
		if strings.EqualFold(strings.TrimSpace(v), needle) {
			return true
		}
	}
	return false
}

func generateToken() (string, []byte, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", nil, err
	}
	raw := base64.RawURLEncoding.EncodeToString(b)
	sum := sha256.Sum256([]byte(raw))
	hash := make([]byte, len(sum))
	copy(hash, sum[:])
	return raw, hash, nil
}

func generateChallengeCode() (string, []byte, error) {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		return "", nil, err
	}
	v := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	raw := strconv.FormatUint(uint64(100000+(v%900000)), 10)
	sum := sha256.Sum256([]byte(raw))
	hash := make([]byte, len(sum))
	copy(hash, sum[:])
	return raw, hash, nil
}

func buildApprovalPage(req ApprovalRequest, token string) string {
	return "<!doctype html><html><head><meta charset=\"utf-8\"><title>Vecta Governance Approval</title></head><body>" +
		"<h2>Approval Required</h2>" +
		"<p><b>Tenant:</b> " + htmlEscape(req.TenantID) + "</p>" +
		"<p><b>Action:</b> " + htmlEscape(req.Action) + "</p>" +
		"<p><b>Target:</b> " + htmlEscape(req.TargetType) + ":" + htmlEscape(req.TargetID) + "</p>" +
		"<p><b>Expires:</b> " + req.ExpiresAt.UTC().Format(time.RFC3339) + "</p>" +
		"<form method=\"post\" action=\"/governance/approve/" + htmlEscape(req.ID) + "\">" +
		"<input type=\"hidden\" name=\"token\" value=\"" + htmlEscape(token) + "\"/>" +
		"<input type=\"hidden\" name=\"tenant_id\" value=\"" + htmlEscape(req.TenantID) + "\"/>" +
		"<label>Comment: <input type=\"text\" name=\"comment\"/></label><br/><br/>" +
		"<button type=\"submit\" name=\"vote\" value=\"approved\">Approve</button>" +
		"<button type=\"submit\" name=\"vote\" value=\"denied\">Deny</button>" +
		"</form></body></html>"
}

func htmlEscape(v string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", "\"", "&quot;", "'", "&#39;")
	return r.Replace(v)
}

func clamp(v int, min int, max int) int {
	if v < min {
		return min
	}
	if v > max {
		return max
	}
	return v
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func newID(prefix string) string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return prefix + "_" + base64.RawURLEncoding.EncodeToString(b)
}

func intFromAny(v interface{}) int {
	switch x := v.(type) {
	case int:
		return x
	case int64:
		return int(x)
	case float64:
		return int(x)
	case string:
		n, _ := strconv.Atoi(strings.TrimSpace(x))
		return n
	default:
		return 0
	}
}

func maxInt(a int, b int) int {
	if a > b {
		return a
	}
	return b
}
