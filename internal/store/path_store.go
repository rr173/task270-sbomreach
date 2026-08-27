package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"task270-sbomreach/internal/model"
)

// PathStore 提供可达路径的 SQLite 持久化。
type PathStore struct {
	db *sql.DB
}

// NewPathStore 构造路径仓库。
func NewPathStore(db *sql.DB) *PathStore {
	return &PathStore{db: db}
}

type execer interface {
	Exec(query string, args ...any) (sql.Result, error)
}

// Insert 插入候选路径。
func (s *PathStore) Insert(p *model.ReachPath) error {
	return insertPath(s.db, p)
}

func insertPath(ex execer, p *model.ReachPath) error {
	hops, err := json.Marshal(p.Hops)
	if err != nil {
		return err
	}
	_, err = ex.Exec(`
		INSERT INTO reach_paths(id, release_id, vuln_id, cve_id, start_symbol, end_symbol,
			status, hops, block_reason, blocked_condition, adjudicated_by, adjudicated_at, created_at)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		p.ID, p.ReleaseID, p.VulnID, p.CVEID, p.StartSymbol, p.EndSymbol,
		string(p.Status), string(hops), p.BlockReason, p.BlockedAt,
		p.AdjudicatedBy, adjudicatedAtString(p.AdjudicatedAt), formatTime(p.CreatedAt))
	if err != nil {
		return mapSQLiteError(err)
	}
	return nil
}

// ReplaceByRelease 在同一事务内清空并写回某发布物的全部路径。
// ctx 取消或任一插入失败时回滚，避免“路径被清空但新结果未落库”的半写状态。
//
// 注意：DELETE 与全部 INSERT 必须同属一个事务、最后才提交，否则一旦 INSERT
// 失败，旧路径已被删光而新路径一条未进，发布物会变成“状态已推进但无路径证据”。
func (s *PathStore) ReplaceByRelease(ctx context.Context, releaseID string, paths []*model.ReachPath) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }() // 未 Commit 时回滚（Commit 后为 no-op）
	if err := replacePathsInTx(tx, releaseID, paths); err != nil {
		return err
	}
	return tx.Commit()
}

// ReplaceByReleaseTx 在调用方提供的事务上执行同样的清空 + 写回，
// 用于把路径重写与发布物状态推进合并成同一次提交。
// 调用方负责 BeginTx / Commit / Rollback；本方法只在该事务上执行 SQL。
func (s *PathStore) ReplaceByReleaseTx(tx *sql.Tx, releaseID string, paths []*model.ReachPath) error {
	return replacePathsInTx(tx, releaseID, paths)
}

// replacePathsInTx 在给定 execer（事务或库句柄）上：先删除旧路径，再全量插入新路径。
// DELETE 与 INSERT 共用同一事务，故任何一步失败都会连同 DELETE 一起回滚。
func replacePathsInTx(ex execer, releaseID string, paths []*model.ReachPath) error {
	if _, err := ex.Exec(`DELETE FROM reach_paths WHERE release_id = ?`, releaseID); err != nil {
		return err
	}
	for _, p := range paths {
		if err := insertPath(ex, p); err != nil {
			return err
		}
	}
	return nil
}

// UpdateStatus 更新路径状态（分析定稿 / 裁决确认）。
func (s *PathStore) UpdateStatus(p *model.ReachPath) error {
	hops, err := json.Marshal(p.Hops)
	if err != nil {
		return err
	}
	res, err := s.db.Exec(`
		UPDATE reach_paths SET status = ?, hops = ?, block_reason = ?, blocked_condition = ?,
			adjudicated_by = ?, adjudicated_at = ?
		WHERE id = ?`,
		string(p.Status), string(hops), p.BlockReason, p.BlockedAt,
		p.AdjudicatedBy, adjudicatedAtString(p.AdjudicatedAt), p.ID)
	if err != nil {
		return err
	}
	return requireAffected(res, "路径 "+p.ID)
}

// Get 按 ID 查询路径。
func (s *PathStore) Get(id string) (*model.ReachPath, error) {
	row := s.db.QueryRow(`
		SELECT id, release_id, vuln_id, cve_id, start_symbol, end_symbol,
			status, hops, block_reason, blocked_condition, adjudicated_by, adjudicated_at, created_at
		FROM reach_paths WHERE id = ?`, id)
	p, err := scanPath(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%w: 路径 %s", model.ErrNotFound, id)
	}
	if err != nil {
		return nil, err
	}
	return p, nil
}

// ListByRelease 列出某发布物的全部路径（按创建时间倒序）。
func (s *PathStore) ListByRelease(releaseID string) ([]*model.ReachPath, error) {
	rows, err := s.db.Query(`
		SELECT id, release_id, vuln_id, cve_id, start_symbol, end_symbol,
			status, hops, block_reason, blocked_condition, adjudicated_by, adjudicated_at, created_at
		FROM reach_paths WHERE release_id = ? ORDER BY created_at DESC`, releaseID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*model.ReachPath{}
	for rows.Next() {
		p, err := scanPath(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func scanPath(row rowScanner) (*model.ReachPath, error) {
	var (
		id, releaseID, vulnID, cveID, start, end string
		status, hops, blockReason, blockedCond   string
		adjudicator, adjudicatedAt, createdAt    string
	)
	if err := row.Scan(&id, &releaseID, &vulnID, &cveID, &start, &end,
		&status, &hops, &blockReason, &blockedCond,
		&adjudicator, &adjudicatedAt, &createdAt); err != nil {
		return nil, err
	}
	var hopList []model.PathHop
	if err := json.Unmarshal([]byte(hops), &hopList); err != nil {
		hopList = []model.PathHop{}
	}
	ct, err := parseTime(createdAt)
	if err != nil {
		return nil, err
	}
	aa, err := nullableTime(sql.NullString{String: adjudicatedAt, Valid: adjudicatedAt != ""})
	if err != nil {
		return nil, err
	}
	return &model.ReachPath{
		ID:            id,
		ReleaseID:     releaseID,
		VulnID:        vulnID,
		CVEID:         cveID,
		StartSymbol:   start,
		EndSymbol:     end,
		Status:        model.PathStatus(status),
		Hops:          hopList,
		BlockReason:   blockReason,
		BlockedAt:     blockedCond,
		AdjudicatedBy: adjudicator,
		AdjudicatedAt: aa,
		CreatedAt:     ct,
	}, nil
}

func adjudicatedAtString(t *time.Time) string {
	if t == nil {
		return ""
	}
	return formatTime(*t)
}
