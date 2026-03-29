package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	pkgdb "vecta-kms/pkg/db"
)

var errNotFound = errors.New("not found")

type Store interface {
	CreatePostureSnapshot(ctx context.Context, item PostureSnapshot) error
	GetLatestPosture(ctx context.Context, tenantID string) (PostureSnapshot, error)
	ListPostureHistory(ctx context.Context, tenantID string, limit int) ([]PostureSnapshot, error)

	UpsertFrameworkAssessment(ctx context.Context, item FrameworkAssessment) error
	GetFrameworkAssessment(ctx context.Context, tenantID string, frameworkID string) (FrameworkAssessment, error)
	ListFrameworkAssessments(ctx context.Context, tenantID string) ([]FrameworkAssessment, error)

	ReplaceFrameworkGaps(ctx context.Context, tenantID string, frameworkID string, gaps []ComplianceGap) error
	ListFrameworkGaps(ctx context.Context, tenantID string, frameworkID string) ([]ComplianceGap, error)

	SaveCBOMSnapshot(ctx context.Context, item CBOMSnapshot) error
	GetLatestCBOMSnapshot(ctx context.Context, tenantID string) (CBOMSnapshot, error)
	ListCBOMSnapshots(ctx context.Context, tenantID string, from time.Time, to time.Time, limit int) ([]CBOMSnapshot, error)

	CreateAssessmentRun(ctx context.Context, item AssessmentResult) error
	ListAssessmentRuns(ctx context.Context, tenantID string, templateID string, limit int) ([]AssessmentResult, error)

	UpsertComplianceTemplate(ctx context.Context, item ComplianceTemplate) error
	GetComplianceTemplate(ctx context.Context, tenantID string, templateID string) (ComplianceTemplate, error)
	ListComplianceTemplates(ctx context.Context, tenantID string) ([]ComplianceTemplate, error)
	DeleteComplianceTemplate(ctx context.Context, tenantID string, templateID string) error

	GetAssessmentSchedule(ctx context.Context, tenantID string) (AssessmentSchedule, error)
	UpsertAssessmentSchedule(ctx context.Context, item AssessmentSchedule) error
	ListDueAssessmentSchedules(ctx context.Context, now time.Time, limit int) ([]AssessmentSchedule, error)
	UpdateAssessmentScheduleRun(ctx context.Context, tenantID string, lastRunAt time.Time, nextRunAt time.Time) error

	// Automated Incident Playbooks
	ListPlaybooks(ctx context.Context, tenantID string) ([]Playbook, error)
	CreatePlaybook(ctx context.Context, p Playbook) (Playbook, error)
	GetPlaybook(ctx context.Context, tenantID, id string) (Playbook, error)
	UpdatePlaybook(ctx context.Context, p Playbook) (Playbook, error)
	DeletePlaybook(ctx context.Context, tenantID, id string) error
	CreatePlaybookRun(ctx context.Context, run PlaybookRun) (PlaybookRun, error)
	UpdatePlaybookRun(ctx context.Context, run PlaybookRun) (PlaybookRun, error)
	IncrementPlaybookRunCount(ctx context.Context, tenantID, id string, lastRunAt time.Time) error
	ListPlaybookRuns(ctx context.Context, tenantID, playbookID string, limit int) ([]PlaybookRun, error)
	GetPlaybookSummary(ctx context.Context, tenantID string) (map[string]interface{}, error)
}

type SQLStore struct {
	db *pkgdb.DB
}

func NewSQLStore(db *pkgdb.DB) *SQLStore {
	return &SQLStore{db: db}
}

func (s *SQLStore) CreatePostureSnapshot(ctx context.Context, item PostureSnapshot) error {
	if item.FrameworkScores == nil {
		item.FrameworkScores = map[string]int{}
	}
	if item.Metrics == nil {
		item.Metrics = map[string]float64{}
	}
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO compliance_posture_snapshots (
	tenant_id, id, overall_score, key_hygiene, policy_compliance, access_security, crypto_posture,
	pqc_readiness, framework_scores, metrics_json, gap_count, created_at
) VALUES (
	$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,CURRENT_TIMESTAMP
)
`, item.TenantID, item.ID, item.OverallScore, item.KeyHygiene, item.PolicyCompliance, item.AccessSecurity, item.CryptoPosture,
		item.PQCReadiness, mustJSON(item.FrameworkScores, "{}"), mustJSON(item.Metrics, "{}"), item.GapCount)
	return err
}

func (s *SQLStore) GetLatestPosture(ctx context.Context, tenantID string) (PostureSnapshot, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT tenant_id, id, overall_score, key_hygiene, policy_compliance, access_security, crypto_posture,
	   pqc_readiness, framework_scores, metrics_json, gap_count, created_at
FROM compliance_posture_snapshots
WHERE tenant_id = $1
ORDER BY created_at DESC
LIMIT 1
`, tenantID)
	item, err := scanPostureSnapshot(row)
	if errors.Is(err, sql.ErrNoRows) {
		return PostureSnapshot{}, errNotFound
	}
	return item, err
}

func (s *SQLStore) ListPostureHistory(ctx context.Context, tenantID string, limit int) ([]PostureSnapshot, error) {
	if limit <= 0 || limit > 365 {
		limit = 30
	}
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT tenant_id, id, overall_score, key_hygiene, policy_compliance, access_security, crypto_posture,
	   pqc_readiness, framework_scores, metrics_json, gap_count, created_at
FROM compliance_posture_snapshots
WHERE tenant_id = $1
ORDER BY created_at DESC
LIMIT $2
`, tenantID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := make([]PostureSnapshot, 0)
	for rows.Next() {
		item, err := scanPostureSnapshot(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *SQLStore) UpsertFrameworkAssessment(ctx context.Context, item FrameworkAssessment) error {
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO compliance_framework_assessments (
	tenant_id, id, framework_id, score, status, controls_json, gaps_json, pqc_ready, qsl_avg, created_at, updated_at
) VALUES (
	$1,$2,$3,$4,$5,$6,$7,$8,$9,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP
)
ON CONFLICT (tenant_id, framework_id) DO UPDATE SET
	score = excluded.score,
	status = excluded.status,
	controls_json = excluded.controls_json,
	gaps_json = excluded.gaps_json,
	pqc_ready = excluded.pqc_ready,
	qsl_avg = excluded.qsl_avg,
	updated_at = CURRENT_TIMESTAMP
`, item.TenantID, item.ID, item.FrameworkID, item.Score, item.Status,
		mustJSON(item.Controls, "[]"), mustJSON(item.Gaps, "[]"), item.PQCReady, item.QSLAvg)
	return err
}

func (s *SQLStore) GetFrameworkAssessment(ctx context.Context, tenantID string, frameworkID string) (FrameworkAssessment, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT tenant_id, id, framework_id, score, status, controls_json, gaps_json, pqc_ready, qsl_avg, created_at, updated_at
FROM compliance_framework_assessments
WHERE tenant_id = $1 AND framework_id = $2
`, tenantID, frameworkID)
	item, err := scanFrameworkAssessment(row)
	if errors.Is(err, sql.ErrNoRows) {
		return FrameworkAssessment{}, errNotFound
	}
	return item, err
}

func (s *SQLStore) ListFrameworkAssessments(ctx context.Context, tenantID string) ([]FrameworkAssessment, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT tenant_id, id, framework_id, score, status, controls_json, gaps_json, pqc_ready, qsl_avg, created_at, updated_at
FROM compliance_framework_assessments
WHERE tenant_id = $1
ORDER BY framework_id
`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := make([]FrameworkAssessment, 0)
	for rows.Next() {
		item, err := scanFrameworkAssessment(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *SQLStore) ReplaceFrameworkGaps(ctx context.Context, tenantID string, frameworkID string, gaps []ComplianceGap) error {
	tx, err := s.db.SQL().BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck

	if _, err := tx.ExecContext(ctx, `
DELETE FROM compliance_gaps
WHERE tenant_id = $1 AND framework_id = $2
`, tenantID, frameworkID); err != nil {
		return err
	}

	for _, g := range gaps {
		detectedAt := g.DetectedAt
		if detectedAt.IsZero() {
			detectedAt = time.Now().UTC()
		}
		if _, err := tx.ExecContext(ctx, `
INSERT INTO compliance_gaps (
	tenant_id, id, framework_id, control_id, severity, title, description, resource_id, status, detected_at, resolved_at
) VALUES (
	$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11
)
`, g.TenantID, g.ID, g.FrameworkID, g.ControlID, g.Severity, g.Title, g.Description, g.ResourceID, defaultString(g.Status, "open"), detectedAt, nullableTime(g.ResolvedAt)); err != nil {
			return err
		}
	}

	return tx.Commit()
}

func (s *SQLStore) ListFrameworkGaps(ctx context.Context, tenantID string, frameworkID string) ([]ComplianceGap, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT tenant_id, id, framework_id, control_id, severity, title, description, resource_id, status, detected_at, resolved_at
FROM compliance_gaps
WHERE tenant_id = $1 AND framework_id = $2
ORDER BY detected_at DESC
`, tenantID, frameworkID)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := make([]ComplianceGap, 0)
	for rows.Next() {
		item, err := scanGap(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *SQLStore) SaveCBOMSnapshot(ctx context.Context, item CBOMSnapshot) error {
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO compliance_cbom_snapshots (
	tenant_id, id, summary_json, document_json, created_at
) VALUES (
	$1,$2,$3,$4,CURRENT_TIMESTAMP
)
`, item.TenantID, item.ID, item.SummaryJSON, item.DocumentJSON)
	return err
}

func (s *SQLStore) GetLatestCBOMSnapshot(ctx context.Context, tenantID string) (CBOMSnapshot, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT tenant_id, id, summary_json, document_json, created_at
FROM compliance_cbom_snapshots
WHERE tenant_id = $1
ORDER BY created_at DESC
LIMIT 1
`, tenantID)
	item, err := scanCBOMSnapshot(row)
	if errors.Is(err, sql.ErrNoRows) {
		return CBOMSnapshot{}, errNotFound
	}
	return item, err
}

func (s *SQLStore) ListCBOMSnapshots(ctx context.Context, tenantID string, from time.Time, to time.Time, limit int) ([]CBOMSnapshot, error) {
	if limit <= 0 || limit > 365 {
		limit = 50
	}
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT tenant_id, id, summary_json, document_json, created_at
FROM compliance_cbom_snapshots
WHERE tenant_id = $1
  AND ($2 IS NULL OR created_at >= $2)
  AND ($3 IS NULL OR created_at <= $3)
ORDER BY created_at DESC
LIMIT $4
`, tenantID, nullableTime(from), nullableTime(to), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := make([]CBOMSnapshot, 0)
	for rows.Next() {
		item, err := scanCBOMSnapshot(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *SQLStore) CreateAssessmentRun(ctx context.Context, item AssessmentResult) error {
	if item.FrameworkScores == nil {
		item.FrameworkScores = map[string]int{}
	}
	if item.Findings == nil {
		item.Findings = []AssessmentFinding{}
	}
	if item.CertMetrics == nil {
		item.CertMetrics = map[string]float64{}
	}
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO compliance_assessment_runs (
	tenant_id, id, trigger, template_id, template_name, overall_score, framework_scores, findings_json, pqc_json, cert_metrics_json, posture_json, created_at
) VALUES (
	$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,CURRENT_TIMESTAMP
)
`, item.TenantID, item.ID, item.Trigger, item.TemplateID, item.TemplateName, item.OverallScore, mustJSON(item.FrameworkScores, "{}"),
		mustJSON(item.Findings, "[]"), mustJSON(item.PQC, "{}"), mustJSON(item.CertMetrics, "{}"), mustJSON(item.Posture, "{}"))
	return err
}

func (s *SQLStore) ListAssessmentRuns(ctx context.Context, tenantID string, templateID string, limit int) ([]AssessmentResult, error) {
	if limit <= 0 || limit > 365 {
		limit = 30
	}
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT tenant_id, id, trigger, template_id, template_name, overall_score, framework_scores, findings_json, pqc_json, cert_metrics_json, posture_json, created_at
FROM compliance_assessment_runs
WHERE tenant_id = $1
  AND (
	$2 = ''
	OR ($2 = 'default' AND (template_id = '' OR template_id = 'default'))
	OR template_id = $2
  )
ORDER BY created_at DESC
LIMIT $3
`, tenantID, strings.TrimSpace(templateID), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := make([]AssessmentResult, 0)
	for rows.Next() {
		item, err := scanAssessmentResult(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *SQLStore) UpsertComplianceTemplate(ctx context.Context, item ComplianceTemplate) error {
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO compliance_templates (
	tenant_id, id, name, description, enabled, frameworks_json, created_at, updated_at
) VALUES (
	$1,$2,$3,$4,$5,$6,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP
)
ON CONFLICT (tenant_id, id) DO UPDATE SET
	name = excluded.name,
	description = excluded.description,
	enabled = excluded.enabled,
	frameworks_json = excluded.frameworks_json,
	updated_at = CURRENT_TIMESTAMP
`, item.TenantID, item.ID, item.Name, item.Description, item.Enabled, mustJSON(item.Frameworks, "[]"))
	return err
}

func (s *SQLStore) GetComplianceTemplate(ctx context.Context, tenantID string, templateID string) (ComplianceTemplate, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT tenant_id, id, name, description, enabled, frameworks_json, created_at, updated_at
FROM compliance_templates
WHERE tenant_id = $1 AND id = $2
`, tenantID, templateID)
	item, err := scanComplianceTemplate(row)
	if errors.Is(err, sql.ErrNoRows) {
		return ComplianceTemplate{}, errNotFound
	}
	return item, err
}

func (s *SQLStore) ListComplianceTemplates(ctx context.Context, tenantID string) ([]ComplianceTemplate, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT tenant_id, id, name, description, enabled, frameworks_json, created_at, updated_at
FROM compliance_templates
WHERE tenant_id = $1
ORDER BY updated_at DESC, name ASC
`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := make([]ComplianceTemplate, 0)
	for rows.Next() {
		item, err := scanComplianceTemplate(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *SQLStore) DeleteComplianceTemplate(ctx context.Context, tenantID string, templateID string) error {
	res, err := s.db.SQL().ExecContext(ctx, `
DELETE FROM compliance_templates
WHERE tenant_id = $1 AND id = $2
`, tenantID, templateID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return errNotFound
	}
	return nil
}

func (s *SQLStore) GetAssessmentSchedule(ctx context.Context, tenantID string) (AssessmentSchedule, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT tenant_id, enabled, frequency, last_run_at, next_run_at, updated_at
FROM compliance_assessment_schedules
WHERE tenant_id = $1
`, tenantID)
	item, err := scanAssessmentSchedule(row)
	if errors.Is(err, sql.ErrNoRows) {
		return AssessmentSchedule{
			TenantID:  tenantID,
			Enabled:   false,
			Frequency: "daily",
		}, nil
	}
	return item, err
}

func (s *SQLStore) UpsertAssessmentSchedule(ctx context.Context, item AssessmentSchedule) error {
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO compliance_assessment_schedules (
	tenant_id, enabled, frequency, last_run_at, next_run_at, updated_at
) VALUES (
	$1,$2,$3,$4,$5,CURRENT_TIMESTAMP
)
ON CONFLICT (tenant_id) DO UPDATE SET
	enabled = excluded.enabled,
	frequency = excluded.frequency,
	last_run_at = excluded.last_run_at,
	next_run_at = excluded.next_run_at,
	updated_at = CURRENT_TIMESTAMP
`, item.TenantID, item.Enabled, item.Frequency, nullableTime(item.LastRunAt), nullableTime(item.NextRunAt))
	return err
}

func (s *SQLStore) ListDueAssessmentSchedules(ctx context.Context, now time.Time, limit int) ([]AssessmentSchedule, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT tenant_id, enabled, frequency, last_run_at, next_run_at, updated_at
FROM compliance_assessment_schedules
WHERE enabled = TRUE
  AND next_run_at IS NOT NULL
  AND next_run_at <= $1
ORDER BY next_run_at ASC
LIMIT $2
`, now.UTC(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := make([]AssessmentSchedule, 0)
	for rows.Next() {
		item, err := scanAssessmentSchedule(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *SQLStore) UpdateAssessmentScheduleRun(ctx context.Context, tenantID string, lastRunAt time.Time, nextRunAt time.Time) error {
	_, err := s.db.SQL().ExecContext(ctx, `
UPDATE compliance_assessment_schedules
SET last_run_at = $1,
    next_run_at = $2,
    updated_at = CURRENT_TIMESTAMP
WHERE tenant_id = $3
`, nullableTime(lastRunAt), nullableTime(nextRunAt), tenantID)
	return err
}

func scanPostureSnapshot(scanner interface {
	Scan(dest ...interface{}) error
}) (PostureSnapshot, error) {
	var (
		item              PostureSnapshot
		frameworkScoresJS string
		metricsJS         string
		createdRaw        interface{}
	)
	err := scanner.Scan(
		&item.TenantID, &item.ID, &item.OverallScore, &item.KeyHygiene, &item.PolicyCompliance, &item.AccessSecurity, &item.CryptoPosture,
		&item.PQCReadiness, &frameworkScoresJS, &metricsJS, &item.GapCount, &createdRaw,
	)
	if err != nil {
		return PostureSnapshot{}, err
	}
	_ = jsonUnmarshalMapInt(frameworkScoresJS, &item.FrameworkScores)
	_ = jsonUnmarshalMapFloat(metricsJS, &item.Metrics)
	item.CreatedAt = parseTimeValue(createdRaw)
	return item, nil
}

func scanFrameworkAssessment(scanner interface {
	Scan(dest ...interface{}) error
}) (FrameworkAssessment, error) {
	var (
		item       FrameworkAssessment
		controlsJS string
		gapsJS     string
		createdRaw interface{}
		updatedRaw interface{}
	)
	err := scanner.Scan(
		&item.TenantID, &item.ID, &item.FrameworkID, &item.Score, &item.Status, &controlsJS, &gapsJS, &item.PQCReady, &item.QSLAvg, &createdRaw, &updatedRaw,
	)
	if err != nil {
		return FrameworkAssessment{}, err
	}
	_ = jsonUnmarshalSliceControls(controlsJS, &item.Controls)
	_ = jsonUnmarshalSliceGaps(gapsJS, &item.Gaps)
	item.CreatedAt = parseTimeValue(createdRaw)
	item.UpdatedAt = parseTimeValue(updatedRaw)
	return item, nil
}

func scanGap(scanner interface {
	Scan(dest ...interface{}) error
}) (ComplianceGap, error) {
	var (
		item        ComplianceGap
		detectedRaw interface{}
		resolvedRaw interface{}
	)
	err := scanner.Scan(
		&item.TenantID, &item.ID, &item.FrameworkID, &item.ControlID, &item.Severity, &item.Title, &item.Description, &item.ResourceID, &item.Status, &detectedRaw, &resolvedRaw,
	)
	if err != nil {
		return ComplianceGap{}, err
	}
	item.DetectedAt = parseTimeValue(detectedRaw)
	item.ResolvedAt = parseTimeValue(resolvedRaw)
	return item, nil
}

func scanCBOMSnapshot(scanner interface {
	Scan(dest ...interface{}) error
}) (CBOMSnapshot, error) {
	var (
		item       CBOMSnapshot
		createdRaw interface{}
	)
	err := scanner.Scan(&item.TenantID, &item.ID, &item.SummaryJSON, &item.DocumentJSON, &createdRaw)
	if err != nil {
		return CBOMSnapshot{}, err
	}
	item.GeneratedAt = parseTimeValue(createdRaw)
	return item, nil
}

func scanAssessmentResult(scanner interface {
	Scan(dest ...interface{}) error
}) (AssessmentResult, error) {
	var (
		item              AssessmentResult
		templateID        string
		templateName      string
		frameworkScoresJS string
		findingsJS        string
		pqcJS             string
		certMetricsJS     string
		postureJS         string
		createdRaw        interface{}
	)
	err := scanner.Scan(
		&item.TenantID, &item.ID, &item.Trigger, &templateID, &templateName, &item.OverallScore, &frameworkScoresJS, &findingsJS, &pqcJS, &certMetricsJS, &postureJS, &createdRaw,
	)
	if err != nil {
		return AssessmentResult{}, err
	}
	item.TemplateID = strings.TrimSpace(templateID)
	item.TemplateName = strings.TrimSpace(templateName)
	_ = jsonUnmarshalMapInt(frameworkScoresJS, &item.FrameworkScores)
	_ = jsonUnmarshalSliceFindings(findingsJS, &item.Findings)
	_ = jsonUnmarshalPQC(pqcJS, &item.PQC)
	_ = jsonUnmarshalMapFloat(certMetricsJS, &item.CertMetrics)
	_ = jsonUnmarshalPosture(postureJS, &item.Posture)
	item.CreatedAt = parseTimeValue(createdRaw)
	return item, nil
}

func scanComplianceTemplate(scanner interface {
	Scan(dest ...interface{}) error
}) (ComplianceTemplate, error) {
	var (
		item         ComplianceTemplate
		frameworksJS string
		createdRaw   interface{}
		updatedRaw   interface{}
	)
	err := scanner.Scan(
		&item.TenantID, &item.ID, &item.Name, &item.Description, &item.Enabled, &frameworksJS, &createdRaw, &updatedRaw,
	)
	if err != nil {
		return ComplianceTemplate{}, err
	}
	_ = jsonUnmarshalSliceTemplateFrameworks(frameworksJS, &item.Frameworks)
	item.CreatedAt = parseTimeValue(createdRaw)
	item.UpdatedAt = parseTimeValue(updatedRaw)
	return item, nil
}

func scanAssessmentSchedule(scanner interface {
	Scan(dest ...interface{}) error
}) (AssessmentSchedule, error) {
	var (
		item       AssessmentSchedule
		lastRunRaw interface{}
		nextRunRaw interface{}
		updatedRaw interface{}
	)
	err := scanner.Scan(&item.TenantID, &item.Enabled, &item.Frequency, &lastRunRaw, &nextRunRaw, &updatedRaw)
	if err != nil {
		return AssessmentSchedule{}, err
	}
	item.LastRunAt = parseTimeValue(lastRunRaw)
	item.NextRunAt = parseTimeValue(nextRunRaw)
	item.UpdatedAt = parseTimeValue(updatedRaw)
	if strings.TrimSpace(item.Frequency) == "" {
		item.Frequency = "daily"
	}
	return item, nil
}

func jsonUnmarshalMapInt(raw string, out *map[string]int) error {
	if out == nil {
		return nil
	}
	if *out == nil {
		*out = map[string]int{}
	}
	return json.Unmarshal([]byte(raw), out)
}

func jsonUnmarshalMapFloat(raw string, out *map[string]float64) error {
	if out == nil {
		return nil
	}
	if *out == nil {
		*out = map[string]float64{}
	}
	return json.Unmarshal([]byte(raw), out)
}

func jsonUnmarshalSliceControls(raw string, out *[]FrameworkControl) error {
	if out == nil {
		return nil
	}
	if *out == nil {
		*out = []FrameworkControl{}
	}
	return json.Unmarshal([]byte(raw), out)
}

func jsonUnmarshalSliceGaps(raw string, out *[]ComplianceGap) error {
	if out == nil {
		return nil
	}
	if *out == nil {
		*out = []ComplianceGap{}
	}
	return json.Unmarshal([]byte(raw), out)
}

func jsonUnmarshalSliceFindings(raw string, out *[]AssessmentFinding) error {
	if out == nil {
		return nil
	}
	if *out == nil {
		*out = []AssessmentFinding{}
	}
	return json.Unmarshal([]byte(raw), out)
}

func jsonUnmarshalPQC(raw string, out *AssessmentPQC) error {
	if out == nil {
		return nil
	}
	return json.Unmarshal([]byte(raw), out)
}

func jsonUnmarshalPosture(raw string, out *PostureSnapshot) error {
	if out == nil {
		return nil
	}
	return json.Unmarshal([]byte(raw), out)
}

func jsonUnmarshalSliceTemplateFrameworks(raw string, out *[]ComplianceTemplateFramework) error {
	if out == nil {
		return nil
	}
	if *out == nil {
		*out = []ComplianceTemplateFramework{}
	}
	return json.Unmarshal([]byte(raw), out)
}

func nullableTime(v time.Time) interface{} {
	if v.IsZero() {
		return nil
	}
	return v.UTC()
}
