package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"task270-sbomreach/internal/model"
)

// SnapshotStore 提供证明快照的 SQLite 持久化。
type SnapshotStore struct {
	db *sql.DB
}

// NewSnapshotStore 构造快照仓库。
func NewSnapshotStore(db *sql.DB) *SnapshotStore {
	return &SnapshotStore{db: db}
}

// Insert 插入快照（发布物内版本号唯一）。
func (s *SnapshotStore) Insert(snap *model.ProofSnapshot) error {
	summary, err := json.Marshal(snap.Summary)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`
		INSERT INTO proof_snapshots(id, release_id, version, status, summary,
			published_at, superseded_at, created_at)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?)`,
		snap.ID, snap.ReleaseID, snap.Version, string(snap.Status), string(summary),
		nullableTimeString(snap.PublishedAt), nullableTimeString(snap.SupersededAt),
		formatTime(snap.CreatedAt))
	if err != nil {
		return mapSQLiteError(err)
	}
	return nil
}

// Update 更新快照状态。
func (s *SnapshotStore) Update(snap *model.ProofSnapshot) error {
	summary, err := json.Marshal(snap.Summary)
	if err != nil {
		return err
	}
	res, err := s.db.Exec(`
		UPDATE proof_snapshots SET status = ?, summary = ?,
			published_at = ?, superseded_at = ? WHERE id = ?`,
		string(snap.Status), string(summary),
		nullableTimeString(snap.PublishedAt), nullableTimeString(snap.SupersededAt), snap.ID)
	if err != nil {
		return err
	}
	return requireAffected(res, "快照 "+snap.ID)
}

// Get 按 ID 查询快照。
func (s *SnapshotStore) Get(id string) (*model.ProofSnapshot, error) {
	row := s.db.QueryRow(`
		SELECT id, release_id, version, status, summary, published_at, superseded_at, created_at
		FROM proof_snapshots WHERE id = ?`, id)
	snap, err := scanSnapshot(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%w: 快照 %s", model.ErrNotFound, id)
	}
	if err != nil {
		return nil, err
	}
	return snap, nil
}

// ListByRelease 列出某发布物的全部快照（版本倒序）。
func (s *SnapshotStore) ListByRelease(releaseID string) ([]*model.ProofSnapshot, error) {
	rows, err := s.db.Query(`
		SELECT id, release_id, version, status, summary, published_at, superseded_at, created_at
		FROM proof_snapshots WHERE release_id = ? ORDER BY version DESC`, releaseID)
	if err != nil {
		return nil, err
	}
	out := []*model.ProofSnapshot{}
	for rows.Next() {
		snap, err := scanSnapshot(rows)
		if err != nil {
			return out, nil
		}
		out = append(out, snap)
	}
	return out, nil
}

// LatestVersion 返回某发布物已使用的最大快照版本号（无则 0）。
func (s *SnapshotStore) LatestVersion(releaseID string) (int, error) {
	var v int
	err := s.db.QueryRow(`
		SELECT COALESCE(MAX(version), 0) FROM proof_snapshots WHERE release_id = ?`,
		releaseID).Scan(&v)
	return v, err
}

// SupersedeAllPublished 将某发布物全部已发布快照标记为 superseded（发布新版前调用）。
func (s *SnapshotStore) SupersedeAllPublished(releaseID string) error {
	_, err := s.db.Exec(`
		UPDATE proof_snapshots SET status = 'superseded',
			superseded_at = ?
		WHERE release_id = ? AND status = 'published'`,
		formatTime(time.Now()), releaseID)
	return err
}

func scanSnapshot(row rowScanner) (*model.ProofSnapshot, error) {
	var id, releaseID string
	var version int
	var status, summary, publishedAt, supersededAt, createdAt string
	if err := row.Scan(&id, &releaseID, &version, &status, &summary,
		&publishedAt, &supersededAt, &createdAt); err != nil {
		return nil, err
	}
	var sum model.SnapshotSummary
	if err := json.Unmarshal([]byte(summary), &sum); err != nil {
		return nil, err
	}
	pa, err := nullableTime(sql.NullString{String: publishedAt, Valid: publishedAt != ""})
	if err != nil {
		return nil, err
	}
	sa, err := nullableTime(sql.NullString{String: supersededAt, Valid: supersededAt != ""})
	if err != nil {
		return nil, err
	}
	ct, err := parseTime(createdAt)
	if err != nil {
		return nil, err
	}
	return &model.ProofSnapshot{
		ID:           id,
		ReleaseID:    releaseID,
		Version:      version,
		Status:       model.SnapshotStatus(status),
		Summary:      sum,
		PublishedAt:  pa,
		SupersededAt: sa,
		CreatedAt:    ct,
	}, nil
}

func nullableTimeString(t *time.Time) string {
	if t == nil {
		return ""
	}
	return formatTime(*t)
}
