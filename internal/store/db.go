package store

import (
	"database/sql"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

// Open 打开（或创建）SQLite 数据库并执行迁移建表。
// 使用纯 Go 驱动 modernc.org/sqlite，CGO 无关，离线可构建。
func Open(path string) (*sql.DB, error) {
	dsn := path + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("打开数据库 %s: %w", path, err)
	}
	db.SetMaxOpenConns(1) // SQLite 单写者，避免并发写锁竞争
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("连接数据库 %s: %w", path, err)
	}
	if err := migrate(db); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("迁移数据库 %s: %w", path, err)
	}
	return db, nil
}

// migrate 执行全部建表迁移（幂等，IF NOT EXISTS）。
func migrate(db *sql.DB) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS releases (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			version TEXT NOT NULL,
			description TEXT NOT NULL DEFAULT '',
			status TEXT NOT NULL,
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL,
			sealed_at TEXT
		)`,
		`CREATE TABLE IF NOT EXISTS components (
			id TEXT PRIMARY KEY,
			release_id TEXT NOT NULL REFERENCES releases(id),
			purl TEXT NOT NULL,
			name TEXT NOT NULL,
			version TEXT NOT NULL,
			type TEXT NOT NULL DEFAULT 'library',
			depends_on TEXT NOT NULL DEFAULT '[]',
			status TEXT NOT NULL,
			exempted_reason TEXT NOT NULL DEFAULT '',
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL,
			UNIQUE(release_id, purl)
		)`,
		`CREATE TABLE IF NOT EXISTS call_edges (
			id TEXT PRIMARY KEY,
			release_id TEXT NOT NULL REFERENCES releases(id),
			source_symbol TEXT NOT NULL,
			target_symbol TEXT NOT NULL,
			condition_ref TEXT NOT NULL DEFAULT '',
			created_at TEXT NOT NULL,
			UNIQUE(release_id, source_symbol, target_symbol, condition_ref)
		)`,
		`CREATE TABLE IF NOT EXISTS vuln_conditions (
			id TEXT PRIMARY KEY,
			release_id TEXT NOT NULL REFERENCES releases(id),
			cve_id TEXT NOT NULL,
			affected_purl TEXT NOT NULL,
			affected_symbol TEXT NOT NULL,
			precondition TEXT NOT NULL DEFAULT '',
			severity TEXT NOT NULL,
			description TEXT NOT NULL DEFAULT '',
			created_at TEXT NOT NULL,
			UNIQUE(release_id, cve_id, affected_symbol)
		)`,
		`CREATE TABLE IF NOT EXISTS deploy_configs (
			release_id TEXT NOT NULL REFERENCES releases(id),
			cfg_key TEXT NOT NULL,
			cfg_value TEXT NOT NULL,
			updated_at TEXT NOT NULL,
			PRIMARY KEY(release_id, cfg_key)
		)`,
		`CREATE TABLE IF NOT EXISTS entry_symbols (
			release_id TEXT NOT NULL REFERENCES releases(id),
			symbol TEXT NOT NULL,
			PRIMARY KEY(release_id, symbol)
		)`,
		`CREATE TABLE IF NOT EXISTS reach_paths (
			id TEXT PRIMARY KEY,
			release_id TEXT NOT NULL REFERENCES releases(id),
			vuln_id TEXT NOT NULL,
			cve_id TEXT NOT NULL,
			start_symbol TEXT NOT NULL,
			end_symbol TEXT NOT NULL,
			status TEXT NOT NULL,
			hops TEXT NOT NULL DEFAULT '[]',
			block_reason TEXT NOT NULL DEFAULT '',
			blocked_condition TEXT NOT NULL DEFAULT '',
			adjudicated_by TEXT NOT NULL DEFAULT '',
			adjudicated_at TEXT,
			created_at TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS exceptions (
			id TEXT PRIMARY KEY,
			release_id TEXT NOT NULL REFERENCES releases(id),
			path_id TEXT NOT NULL,
			cve_id TEXT NOT NULL,
			reason TEXT NOT NULL,
			adjudicated_by TEXT NOT NULL,
			created_at TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS proof_snapshots (
			id TEXT PRIMARY KEY,
			release_id TEXT NOT NULL REFERENCES releases(id),
			version INTEGER NOT NULL,
			status TEXT NOT NULL,
			summary TEXT NOT NULL DEFAULT '{}',
			published_at TEXT,
			superseded_at TEXT,
			created_at TEXT NOT NULL,
			UNIQUE(release_id, version)
		)`,
		`CREATE TABLE IF NOT EXISTS sbom_imports (
			id TEXT PRIMARY KEY,
			release_id TEXT NOT NULL REFERENCES releases(id),
			format TEXT NOT NULL,
			source TEXT NOT NULL DEFAULT '',
			imported_at TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS meta (
			meta_key TEXT PRIMARY KEY,
			meta_value TEXT NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_components_release ON components(release_id)`,
		`CREATE INDEX IF NOT EXISTS idx_edges_release ON call_edges(release_id)`,
		`CREATE INDEX IF NOT EXISTS idx_vulns_release ON vuln_conditions(release_id)`,
		`CREATE INDEX IF NOT EXISTS idx_paths_release ON reach_paths(release_id)`,
		`CREATE INDEX IF NOT EXISTS idx_paths_vuln ON reach_paths(vuln_id)`,
		`CREATE INDEX IF NOT EXISTS idx_snapshots_release ON proof_snapshots(release_id)`,
	}
	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			return fmt.Errorf("执行迁移失败: %w (%s)", err, s)
		}
	}
	return nil
}

// formatTime 将时间格式化为 RFC3339Nano 存储串。
func formatTime(t time.Time) string {
	return t.UTC().Format(time.RFC3339Nano)
}

// parseTime 从存储串解析时间。
func parseTime(s string) (time.Time, error) {
	return time.Parse(time.RFC3339Nano, s)
}

// nullableTime 读取可空时间列。
func nullableTime(s sql.NullString) (*time.Time, error) {
	if !s.Valid || s.String == "" {
		return nil, nil
	}
	t, err := parseTime(s.String)
	if err != nil {
		return nil, err
	}
	return &t, nil
}
