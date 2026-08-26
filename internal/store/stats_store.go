package store

import (
	"database/sql"

	"task270-sbomreach/internal/model"
)

// StatsSnapshot 是一次统计查询的输出视图。
type StatsSnapshot struct {
	Releases      int `json:"releases"`
	Components    int `json:"components"`
	CallEdges     int `json:"call_edges"`
	Vulns         int `json:"vulns"`
	ReachPaths    int `json:"reach_paths"`
	Exceptions    int `json:"exceptions"`
	Snapshots     int `json:"snapshots"`
	ReachableVulns int `json:"reachable_vulns"`
	BlockedVulns  int `json:"blocked_vulns"`
}

// StatsStore 提供跨实体的聚合统计查询。
type StatsStore struct {
	db *sql.DB
}

// NewStatsStore 构造统计仓库。
func NewStatsStore(db *sql.DB) *StatsStore {
	return &StatsStore{db: db}
}

// Overview 汇总全局统计。
func (s *StatsStore) Overview() (*StatsSnapshot, error) {
	out := &StatsSnapshot{}
	counts := []struct {
		sql string
		dst *int
	}{
		{`SELECT COUNT(*) FROM releases`, &out.Releases},
		{`SELECT COUNT(*) FROM components`, &out.Components},
		{`SELECT COUNT(*) FROM call_edges`, &out.CallEdges},
		{`SELECT COUNT(*) FROM vuln_conditions`, &out.Vulns},
		{`SELECT COUNT(*) FROM reach_paths`, &out.ReachPaths},
		{`SELECT COUNT(*) FROM exceptions`, &out.Exceptions},
		{`SELECT COUNT(*) FROM proof_snapshots`, &out.Snapshots},
	}
	for _, c := range counts {
		if err := s.db.QueryRow(c.sql).Scan(c.dst); err != nil {
			return nil, err
		}
	}
	if err := s.db.QueryRow(`
		SELECT COUNT(*) FROM reach_paths WHERE status IN ('reachable', 'confirmed')`).
		Scan(&out.ReachableVulns); err != nil {
		return nil, err
	}
	if err := s.db.QueryRow(`
		SELECT COUNT(*) FROM reach_paths WHERE status = 'blocked'`).
		Scan(&out.BlockedVulns); err != nil {
		return nil, err
	}
	return out, nil
}

// ReleaseStats 统计某发布物的明细规模。
func (s *StatsStore) ReleaseStats(releaseID string) (*model.Release, *StatsSnapshot, error) {
	rel, err := NewReleaseStore(s.db).Get(releaseID)
	if err != nil {
		return nil, nil, err
	}
	st := &StatsSnapshot{}
	counts := []struct {
		sql string
		dst *int
	}{
		{`SELECT COUNT(*) FROM components WHERE release_id = ?`, &st.Components},
		{`SELECT COUNT(*) FROM call_edges WHERE release_id = ?`, &st.CallEdges},
		{`SELECT COUNT(*) FROM vuln_conditions WHERE release_id = ?`, &st.Vulns},
		{`SELECT COUNT(*) FROM reach_paths WHERE release_id = ?`, &st.ReachPaths},
		{`SELECT COUNT(*) FROM exceptions WHERE release_id = ?`, &st.Exceptions},
		{`SELECT COUNT(*) FROM proof_snapshots WHERE release_id = ?`, &st.Snapshots},
	}
	for _, c := range counts {
		if err := s.db.QueryRow(c.sql, releaseID).Scan(c.dst); err != nil {
			return nil, nil, err
		}
	}
	if err := s.db.QueryRow(`
		SELECT COUNT(*) FROM reach_paths WHERE release_id = ? AND status IN ('reachable', 'confirmed')`,
		releaseID).Scan(&st.ReachableVulns); err != nil {
		return nil, nil, err
	}
	if err := s.db.QueryRow(`
		SELECT COUNT(*) FROM reach_paths WHERE release_id = ? AND status = 'blocked'`,
		releaseID).Scan(&st.BlockedVulns); err != nil {
		return nil, nil, err
	}
	return rel, st, nil
}

// SBOMImportStore 提供 SBOM 导入批次记录。
type SBOMImportStore struct {
	db *sql.DB
}

// NewSBOMImportStore 构造导入批次仓库。
func NewSBOMImportStore(db *sql.DB) *SBOMImportStore {
	return &SBOMImportStore{db: db}
}

// Record 记录一次 SBOM 导入。
func (s *SBOMImportStore) Record(releaseID, format, source string) error {
	_, err := s.db.Exec(`
		INSERT INTO sbom_imports(id, release_id, format, source, imported_at)
		VALUES(?, ?, ?, ?, datetime('now'))`,
		"imp-"+releaseID+"-"+format, releaseID, format, source)
	return err
}
