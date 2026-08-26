package store

import (
	"database/sql"
	"errors"
	"fmt"

	"task270-sbomreach/internal/model"
)

// CallEdgeStore 提供调用边的 SQLite 持久化。
type CallEdgeStore struct {
	db *sql.DB
}

// NewCallEdgeStore 构造调用边仓库。
func NewCallEdgeStore(db *sql.DB) *CallEdgeStore {
	return &CallEdgeStore{db: db}
}

// Insert 插入调用边（三元组唯一，冲突时报冲突错误）。
func (s *CallEdgeStore) Insert(e *model.CallEdge) error {
	_, err := s.db.Exec(`
		INSERT INTO call_edges(id, release_id, source_symbol, target_symbol, condition_ref, created_at)
		VALUES(?, ?, ?, ?, ?, ?)`,
		e.ID, e.ReleaseID, e.SourceSymbol, e.TargetSymbol, e.ConditionRef,
		formatTime(e.CreatedAt))
	if err != nil {
		return mapSQLiteError(err)
	}
	return nil
}

// Get 按 ID 查询调用边。
func (s *CallEdgeStore) Get(id string) (*model.CallEdge, error) {
	row := s.db.QueryRow(`
		SELECT id, release_id, source_symbol, target_symbol, condition_ref, created_at
		FROM call_edges WHERE id = ?`, id)
	e, err := scanCallEdge(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%w: 调用边 %s", model.ErrNotFound, id)
	}
	if err != nil {
		return nil, err
	}
	return e, nil
}

// ListByRelease 列出某发布物的全部调用边。
func (s *CallEdgeStore) ListByRelease(releaseID string) ([]*model.CallEdge, error) {
	rows, err := s.db.Query(`
		SELECT id, release_id, source_symbol, target_symbol, condition_ref, created_at
		FROM call_edges WHERE release_id = ? ORDER BY source_symbol, target_symbol`, releaseID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*model.CallEdge{}
	for rows.Next() {
		e, err := scanCallEdge(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// CountByRelease 返回某发布物的调用边数量。
func (s *CallEdgeStore) CountByRelease(releaseID string) (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM call_edges WHERE release_id = ?`, releaseID).Scan(&n)
	return n, err
}

// CollectReferencedSymbols 收集调用摘要中出现的全部符号（源+目标）。
func (s *CallEdgeStore) CollectReferencedSymbols(releaseID string) (map[string]bool, error) {
	rows, err := s.db.Query(`
		SELECT source_symbol FROM call_edges WHERE release_id = ?
		UNION
		SELECT target_symbol FROM call_edges WHERE release_id = ?`, releaseID, releaseID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	symbols := map[string]bool{}
	for rows.Next() {
		var sym string
		if err := rows.Scan(&sym); err != nil {
			return nil, err
		}
		symbols[sym] = true
	}
	return symbols, rows.Err()
}

func scanCallEdge(row rowScanner) (*model.CallEdge, error) {
	var id, releaseID, source, target, condRef, createdAt string
	if err := row.Scan(&id, &releaseID, &source, &target, &condRef, &createdAt); err != nil {
		return nil, err
	}
	ct, err := parseTime(createdAt)
	if err != nil {
		return nil, err
	}
	return &model.CallEdge{
		ID:           id,
		ReleaseID:    releaseID,
		SourceSymbol: source,
		TargetSymbol: target,
		ConditionRef: condRef,
		CreatedAt:    ct,
	}, nil
}
