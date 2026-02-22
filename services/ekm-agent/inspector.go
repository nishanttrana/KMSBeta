package main

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	_ "github.com/microsoft/go-mssqldb"
	_ "github.com/sijms/go-ora/v2"
)

type TDEInspector interface {
	State(ctx context.Context) (string, map[string]interface{}, error)
}

func NewTDEInspector(cfg AgentConfig) TDEInspector {
	engine := strings.ToLower(strings.TrimSpace(cfg.DBEngine))
	switch engine {
	case "oracle":
		return &oracleInspector{cfg: cfg}
	case "mssql":
		return &mssqlInspector{cfg: cfg}
	default:
		return &noopInspector{cfg: cfg}
	}
}

type noopInspector struct {
	cfg AgentConfig
}

func (i *noopInspector) State(_ context.Context) (string, map[string]interface{}, error) {
	return "unknown", map[string]interface{}{
		"engine": i.cfg.DBEngine,
		"mode":   "unsupported_engine",
	}, nil
}

type mssqlInspector struct {
	cfg AgentConfig
}

func (i *mssqlInspector) State(ctx context.Context) (string, map[string]interface{}, error) {
	dsn := strings.TrimSpace(i.cfg.DBDSN)
	if dsn == "" {
		return "unknown", map[string]interface{}{
			"engine": "mssql",
			"mode":   "db_dsn_not_configured",
		}, nil
	}
	db, err := sql.Open("sqlserver", dsn)
	if err != nil {
		return "unknown", map[string]interface{}{
			"engine": "mssql",
			"mode":   "connect_failed",
		}, err
	}
	defer db.Close() //nolint:errcheck
	pingCtx, pingCancel := context.WithTimeout(ctx, 8*time.Second)
	defer pingCancel()
	if err := db.PingContext(pingCtx); err != nil {
		return "unknown", map[string]interface{}{
			"engine": "mssql",
			"mode":   "ping_failed",
		}, err
	}

	const q = `
SELECT TOP 1
  d.name AS db_name,
  dek.encryption_state,
  dek.encryptor_type,
  dek.key_algorithm,
  dek.key_length
FROM sys.dm_database_encryption_keys dek
JOIN sys.databases d ON d.database_id = dek.database_id
ORDER BY dek.modify_date DESC
`
	row := db.QueryRowContext(ctx, q)
	var (
		dbName        sql.NullString
		state         sql.NullInt64
		encryptorType sql.NullString
		keyAlgorithm  sql.NullString
		keyLength     sql.NullInt64
	)
	if err := row.Scan(&dbName, &state, &encryptorType, &keyAlgorithm, &keyLength); err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "no rows") {
			return "disabled", map[string]interface{}{
				"engine":      "mssql",
				"database":    i.cfg.DBName,
				"db_reported": false,
			}, nil
		}
		return "unknown", map[string]interface{}{
			"engine": "mssql",
			"mode":   "query_failed",
		}, err
	}
	tdeState := mapMSSQLEncryptionState(int(state.Int64))
	return tdeState, map[string]interface{}{
		"engine":           "mssql",
		"database":         nullString(dbName),
		"encryption_state": int(state.Int64),
		"encryptor_type":   nullString(encryptorType),
		"key_algorithm":    nullString(keyAlgorithm),
		"key_length":       int(keyLength.Int64),
	}, nil
}

type oracleInspector struct {
	cfg AgentConfig
}

func (i *oracleInspector) State(ctx context.Context) (string, map[string]interface{}, error) {
	dsn := strings.TrimSpace(i.cfg.DBDSN)
	if dsn == "" {
		return "unknown", map[string]interface{}{
			"engine": "oracle",
			"mode":   "db_dsn_not_configured",
		}, nil
	}
	db, err := sql.Open("oracle", dsn)
	if err != nil {
		return "unknown", map[string]interface{}{
			"engine": "oracle",
			"mode":   "connect_failed",
		}, err
	}
	defer db.Close() //nolint:errcheck
	pingCtx, pingCancel := context.WithTimeout(ctx, 8*time.Second)
	defer pingCancel()
	if err := db.PingContext(pingCtx); err != nil {
		return "unknown", map[string]interface{}{
			"engine": "oracle",
			"mode":   "ping_failed",
		}, err
	}

	// Wallet status indicates TDE availability in Oracle.
	const walletQ = `SELECT STATUS, WALLET_TYPE, WRL_PARAMETER FROM V$ENCRYPTION_WALLET`
	row := db.QueryRowContext(ctx, walletQ)
	var (
		status      sql.NullString
		walletType  sql.NullString
		walletParam sql.NullString
	)
	if err := row.Scan(&status, &walletType, &walletParam); err != nil {
		return "unknown", map[string]interface{}{
			"engine": "oracle",
			"mode":   "query_failed",
		}, err
	}
	walletStatus := strings.ToUpper(strings.TrimSpace(status.String))
	tdeState := "disabled"
	switch walletStatus {
	case "OPEN", "OPEN_NO_MASTER_KEY":
		tdeState = "enabled"
	case "CLOSED", "NOT_AVAILABLE":
		tdeState = "disabled"
	default:
		tdeState = "unknown"
	}
	return tdeState, map[string]interface{}{
		"engine":        "oracle",
		"wallet_status": walletStatus,
		"wallet_type":   nullString(walletType),
		"wallet_path":   nullString(walletParam),
	}, nil
}

func mapMSSQLEncryptionState(v int) string {
	switch v {
	case 3:
		return "enabled"
	case 2, 4, 5, 6:
		return "encrypting"
	case 1:
		return "disabled"
	default:
		return "unknown"
	}
}

func nullString(v sql.NullString) string {
	if !v.Valid {
		return ""
	}
	return strings.TrimSpace(v.String)
}

func inspectorError(engine string, mode string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s_%s: %w", engine, mode, err)
}
