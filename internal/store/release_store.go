package store

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	"task270-sbomreach/internal/model"
)

// ReleaseStore 提供发布物的 SQLite 持久化。
type ReleaseStore struct {
	db *sql.DB
}

// NewReleaseStore 构造发布物仓库。
func NewReleaseStore(db *sql.DB) *ReleaseStore {
	return &ReleaseStore{db: db}
}

// Insert 插入发布物（存在同 ID 则冲突）。
func (s *ReleaseStore) Insert(r *model.Release) error {
	_, err := s.db.Exec(`
		INSERT INTO releases(id, name, version, description, status, created_at, updated_at, sealed_at)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?)`,
		r.ID, r.Name, r.Version, r.Description, string(r.Status),
		formatTime(r.CreatedAt), formatTime(r.UpdatedAt), sealedAtString(r.SealedAt))
	if err != nil {
		return mapSQLiteError(err)
	}
	return nil
}

// Update 更新发布物元数据与状态。
func (s *ReleaseStore) Update(r *model.Release) error {
	res, err := s.db.Exec(`
		UPDATE releases SET name=?, version=?, description=?, status=?, updated_at=?, sealed_at=?
		WHERE id=?`,
		r.Name, r.Version, r.Description, string(r.Status),
		formatTime(r.UpdatedAt), sealedAtString(r.SealedAt), r.ID)
	if err != nil {
		return err
	}
	return requireAffected(res, "发布物 "+r.ID)
}

// Get 按 ID 查询发布物。
func (s *ReleaseStore) Get(id string) (*model.Release, error) {
	row := s.db.QueryRow(`
		SELECT id, name, version, description, status, created_at, updated_at, sealed_at
		FROM releases WHERE id = ?`, id)
	r, err := scanRelease(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%w: 发布物 %s", model.ErrNotFound, id)
	}
	if err != nil {
		return nil, err
	}
	return r, nil
}

// List 列出全部发布物（按创建时间倒序）。
func (s *ReleaseStore) List(limit, offset int) ([]*model.Release, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := s.db.Query(`
		SELECT id, name, version, description, status, created_at, updated_at, sealed_at
		FROM releases ORDER BY created_at DESC LIMIT ? OFFSET ?`, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*model.Release{}
	for rows.Next() {
		r, err := scanRelease(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// Count 返回发布物总数。
func (s *ReleaseStore) Count() (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM releases`).Scan(&n)
	return n, err
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanRelease(row rowScanner) (*model.Release, error) {
	var (
		id, name, version, description, status string
		createdAt, updatedAt                   string
		sealedAt                               sql.NullString
	)
	if err := row.Scan(&id, &name, &version, &description, &status,
		&createdAt, &updatedAt, &sealedAt); err != nil {
		return nil, err
	}
	ct, err := parseTime(createdAt)
	if err != nil {
		return nil, err
	}
	ut, err := parseTime(updatedAt)
	if err != nil {
		return nil, err
	}
	sa, err := nullableTime(sealedAt)
	if err != nil {
		return nil, err
	}
	return &model.Release{
		ID:          id,
		Name:        name,
		Version:     version,
		Description: description,
		Status:      model.ReleaseStatus(status),
		CreatedAt:   ct,
		UpdatedAt:   ut,
		SealedAt:    sa,
	}, nil
}

func sealedAtString(t *time.Time) string {
	if t == nil {
		return ""
	}
	return formatTime(*t)
}

func requireAffected(res sql.Result, what string) error {
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("%w: %s", model.ErrNotFound, what)
	}
	return nil
}
