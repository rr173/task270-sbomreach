package service

import (
	"fmt"

	"task270-sbomreach/internal/model"
	"task270-sbomreach/internal/snapshot"
	"task270-sbomreach/internal/store"
)

// SnapshotService 编排证明快照的创建与发布（service 层外观）。
type SnapshotService struct {
	releases *store.ReleaseStore
	paths    *store.PathStore
	snapshots *store.SnapshotStore
	exceptions *store.ExceptionStore
}

// NewSnapshotService 构造快照服务外观。
func NewSnapshotService(releases *store.ReleaseStore, paths *store.PathStore,
	snapshots *store.SnapshotStore, exceptions *store.ExceptionStore) *SnapshotService {
	return &SnapshotService{
		releases:  releases,
		paths:     paths,
		snapshots: snapshots,
		exceptions: exceptions,
	}
}

// CreateDraft 从发布物当前分析结果创建草稿快照。
// 要求发布物至少处于 pending_review（已有路径证据）。
func (s *SnapshotService) CreateDraft(releaseID, vulnDBVersion string) (*model.ProofSnapshot, error) {
	rel, err := s.releases.Get(releaseID)
	if err != nil {
		return nil, err
	}
	if rel.Status == model.ReleaseSealed {
		return nil, fmt.Errorf("发布物 %s 已封存，禁止再建快照", rel.Name)
	}
	if rel.Status != model.ReleasePendingReview && rel.Status != model.ReleasePublishable {
		return nil, fmt.Errorf(
			"%w: 发布物 %s 处于 %s，尚无分析证据，请先运行分析",
			model.ErrStateTransition, rel.Name, rel.Status)
	}
	inner := snapshot.NewService(s.snapshots, s.paths, s.exceptions)
	summary, err := inner.FreezeSummary(releaseID, vulnDBVersion)
	if err != nil {
		return nil, err
	}
	return inner.CreateDraft(releaseID, *summary)
}

// Publish 发布快照并推进发布物到 publishable。
func (s *SnapshotService) Publish(snapID string) (*model.ProofSnapshot, error) {
	inner := snapshot.NewService(s.snapshots, s.paths, s.exceptions)
	snap, err := inner.Publish(snapID)
	if err != nil {
		return nil, err
	}
	// 有已发布快照后，发布物可推进为 publishable（幂等）
	rel, err := s.releases.Get(snap.ReleaseID)
	if err != nil {
		return nil, err
	}
	if rel.Status == model.ReleasePendingReview {
		if _, err := rel.Advance(); err != nil {
			return nil, err
		}
		if err := s.releases.Update(rel); err != nil {
			return nil, err
		}
	}
	return snap, nil
}

// Get 查询快照。
func (s *SnapshotService) Get(snapID string) (*model.ProofSnapshot, error) {
	inner := snapshot.NewService(s.snapshots, s.paths, s.exceptions)
	return inner.Get(snapID)
}

// ListByRelease 列出发布物的全部快照。
func (s *SnapshotService) ListByRelease(releaseID string) ([]*model.ProofSnapshot, error) {
	inner := snapshot.NewService(s.snapshots, s.paths, s.exceptions)
	return inner.ListByRelease(releaseID)
}
