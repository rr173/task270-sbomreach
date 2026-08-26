package store

import (
	"database/sql"
	"errors"
	"fmt"

	"task270-sbomreach/internal/model"
)

// VulnStore 提供漏洞条件的 SQLite 持久化。
type VulnStore struct {
	db *sql.DB
}

// NewVulnStore 构造漏洞条件仓库。
func NewVulnStore(db *sql.DB) *VulnStore {
	return &VulnStore{db: db}
}

// Insert 插入漏洞条件（CVE + 受影响符号唯一，冲突时报冲突）。
func (s *VulnStore) Insert(v *model.VulnCondition) error {
	_, err := s.db.Exec(`
		INSERT INTO vuln_conditions(id, release_id, cve_id, affected_purl, affected_symbol,
			precondition, severity, description, created_at)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		v.ID, v.ReleaseID, v.CVEID, v.AffectedPURL, v.AffectedSymbol,
		v.Precondition, string(v.Severity), v.Description, formatTime(v.CreatedAt))
	if err != nil {
		return mapSQLiteError(err)
	}
	return nil
}

// Get 按 ID 查询漏洞条件。
func (s *VulnStore) Get(id string) (*model.VulnCondition, error) {
	row := s.db.QueryRow(`
		SELECT id, release_id, cve_id, affected_purl, affected_symbol,
			precondition, severity, description, created_at
		FROM vuln_conditions WHERE id = ?`, id)
	v, err := scanVuln(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%w: 漏洞条件 %s", model.ErrNotFound, id)
	}
	if err != nil {
		return nil, err
	}
	return v, nil
}

// ListByRelease 列出某发布物的全部漏洞条件。
func (s *VulnStore) ListByRelease(releaseID string) ([]*model.VulnCondition, error) {
	rows, err := s.db.Query(`
		SELECT id, release_id, cve_id, affected_purl, affected_symbol,
			precondition, severity, description, created_at
		FROM vuln_conditions WHERE release_id = ? ORDER BY cve_id`, releaseID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*model.VulnCondition{}
	for rows.Next() {
		v, err := scanVuln(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// CountByRelease 返回某发布物的漏洞条件数量。
func (s *VulnStore) CountByRelease(releaseID string) (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM vuln_conditions WHERE release_id = ?`, releaseID).Scan(&n)
	return n, err
}

func scanVuln(row rowScanner) (*model.VulnCondition, error) {
	var id, releaseID, cveID, purl, symbol, precondition, sev, desc, createdAt string
	if err := row.Scan(&id, &releaseID, &cveID, &purl, &symbol, &precondition,
		&sev, &desc, &createdAt); err != nil {
		return nil, err
	}
	ct, err := parseTime(createdAt)
	if err != nil {
		return nil, err
	}
	return &model.VulnCondition{
		ID:             id,
		ReleaseID:      releaseID,
		CVEID:          cveID,
		AffectedPURL:   purl,
		AffectedSymbol: symbol,
		Precondition:   precondition,
		Severity:       model.Severity(sev),
		Description:    desc,
		CreatedAt:      ct,
	}, nil
}
