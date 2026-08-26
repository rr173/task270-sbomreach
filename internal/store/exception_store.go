package store

import (
	"database/sql"
	"errors"
	"fmt"

	"task270-sbomreach/internal/model"
)

// ExceptionStore 提供例外记录的 SQLite 持久化。
type ExceptionStore struct {
	db *sql.DB
}

// NewExceptionStore 构造例外仓库。
func NewExceptionStore(db *sql.DB) *ExceptionStore {
	return &ExceptionStore{db: db}
}

// Insert 插入例外记录。
func (s *ExceptionStore) Insert(e *model.Exception) error {
	_, err := s.db.Exec(`
		INSERT INTO exceptions(id, release_id, path_id, cve_id, reason, adjudicated_by, created_at)
		VALUES(?, ?, ?, ?, ?, ?, ?)`,
		e.ID, e.ReleaseID, e.PathID, e.CVEID, e.Reason, e.AdjudicatedBy,
		formatTime(e.CreatedAt))
	if err != nil {
		return mapSQLiteError(err)
	}
	return nil
}

// Get 按 ID 查询例外。
func (s *ExceptionStore) Get(id string) (*model.Exception, error) {
	row := s.db.QueryRow(`
		SELECT id, release_id, path_id, cve_id, reason, adjudicated_by, created_at
		FROM exceptions WHERE id = ?`, id)
	e, err := scanException(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%w: 例外 %s", model.ErrNotFound, id)
	}
	if err != nil {
		return nil, err
	}
	return e, nil
}

// ListByRelease 列出某发布物的全部例外。
func (s *ExceptionStore) ListByRelease(releaseID string) ([]*model.Exception, error) {
	rows, err := s.db.Query(`
		SELECT id, release_id, path_id, cve_id, reason, adjudicated_by, created_at
		FROM exceptions WHERE release_id = ? ORDER BY created_at DESC`, releaseID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*model.Exception{}
	for rows.Next() {
		e, err := scanException(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// CountByRelease 返回某发布物的例外数量。
func (s *ExceptionStore) CountByRelease(releaseID string) (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM exceptions WHERE release_id = ?`, releaseID).Scan(&n)
	return n, err
}

func scanException(row rowScanner) (*model.Exception, error) {
	var id, releaseID, pathID, cveID, reason, adjudicator, createdAt string
	if err := row.Scan(&id, &releaseID, &pathID, &cveID, &reason, &adjudicator, &createdAt); err != nil {
		return nil, err
	}
	ct, err := parseTime(createdAt)
	if err != nil {
		return nil, err
	}
	return &model.Exception{
		ID:            id,
		ReleaseID:     releaseID,
		PathID:        pathID,
		CVEID:         cveID,
		Reason:        reason,
		AdjudicatedBy: adjudicator,
		CreatedAt:     ct,
	}, nil
}
