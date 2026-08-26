package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"task270-sbomreach/internal/model"
)

// ComponentStore 提供构件的 SQLite 持久化。
type ComponentStore struct {
	db *sql.DB
}

// NewComponentStore 构造构件仓库。
func NewComponentStore(db *sql.DB) *ComponentStore {
	return &ComponentStore{db: db}
}

// Upsert 幂等插入构件：同发布物下 PURL 冲突时更新（版本/依赖/类型）。
// 返回 (是否新增, 错误)。
func (s *ComponentStore) Upsert(c *model.Component) (bool, error) {
	deps, err := json.Marshal(c.DependsOn)
	if err != nil {
		return false, err
	}
	res, err := s.db.Exec(`
		INSERT INTO components(id, release_id, purl, name, version, type, depends_on,
			status, exempted_reason, created_at, updated_at)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(release_id, purl) DO UPDATE SET
			name = excluded.name,
			version = excluded.version,
			type = excluded.type,
			depends_on = excluded.depends_on,
			updated_at = excluded.updated_at`,
		c.ID, c.ReleaseID, c.PURL, c.Name, c.Version, c.Type, string(deps),
		string(c.Status), c.ExemptedReason, formatTime(c.CreatedAt), formatTime(c.UpdatedAt))
	if err != nil {
		return false, mapSQLiteError(err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n == 1, nil
}

// Get 按 ID 查询构件。
func (s *ComponentStore) Get(id string) (*model.Component, error) {
	row := s.db.QueryRow(`
		SELECT id, release_id, purl, name, version, type, depends_on,
			status, exempted_reason, created_at, updated_at
		FROM components WHERE id = ?`, id)
	c, err := scanComponent(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%w: 构件 %s", model.ErrNotFound, id)
	}
	if err != nil {
		return nil, err
	}
	return c, nil
}

// ListByRelease 列出某发布物的全部构件。
func (s *ComponentStore) ListByRelease(releaseID string) ([]*model.Component, error) {
	rows, err := s.db.Query(`
		SELECT id, release_id, purl, name, version, type, depends_on,
			status, exempted_reason, created_at, updated_at
		FROM components WHERE release_id = ? ORDER BY purl`, releaseID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*model.Component{}
	for rows.Next() {
		c, err := scanComponent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// UpdateStatus 更新构件状态（用于解析/易受影响/豁免流转）。
func (s *ComponentStore) UpdateStatus(id, status, exemptedReason string) error {
	res, err := s.db.Exec(`
		UPDATE components SET status = ?, exempted_reason = ?, updated_at = ?
		WHERE id = ?`,
		status, exemptedReason, formatTime(time.Now()), id)
	if err != nil {
		return err
	}
	return requireAffected(res, "构件 "+id)
}

func scanComponent(row rowScanner) (*model.Component, error) {
	var (
		id, releaseID, purl, name, version, typ, deps string
		status, exemptedReason, createdAt, updatedAt  string
	)
	if err := row.Scan(&id, &releaseID, &purl, &name, &version, &typ, &deps,
		&status, &exemptedReason, &createdAt, &updatedAt); err != nil {
		return nil, err
	}
	var depList []string
	if err := json.Unmarshal([]byte(deps), &depList); err != nil {
		depList = []string{}
	}
	ct, err := parseTime(createdAt)
	if err != nil {
		return nil, err
	}
	ut, err := parseTime(updatedAt)
	if err != nil {
		return nil, err
	}
	return &model.Component{
		ID:             id,
		ReleaseID:      releaseID,
		PURL:           purl,
		Name:           name,
		Version:        version,
		Type:           typ,
		DependsOn:      depList,
		Status:         model.ComponentStatus(status),
		ExemptedReason: exemptedReason,
		CreatedAt:      ct,
		UpdatedAt:      ut,
	}, nil
}
