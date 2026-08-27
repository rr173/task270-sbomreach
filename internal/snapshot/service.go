// Package snapshot 管理漏洞可达性证明快照的创建、发布与替代。
package snapshot

import (
	"fmt"

	"task270-sbomreach/internal/model"
	"task270-sbomreach/internal/store"
)

// Service 提供快照生命周期编排。
type Service struct {
	snapshots *store.SnapshotStore
	paths     *store.PathStore
	exceptions *store.ExceptionStore
}

// NewService 构造快照服务。
func NewService(snapshots *store.SnapshotStore, paths *store.PathStore,
	exceptions *store.ExceptionStore) *Service {
	return &Service{snapshots: snapshots, paths: paths, exceptions: exceptions}
}

// CreateDraft 基于某发布物的当前分析结果创建草稿快照（版本号自动递增）。
// summary 由调用方（analysis service）构造。
func (s *Service) CreateDraft(releaseID string, summary model.SnapshotSummary) (*model.ProofSnapshot, error) {
	latest, err := s.snapshots.LatestVersion(releaseID)
	if err != nil {
		return nil, err
	}
	snap := model.NewProofSnapshot(releaseID, latest+1, summary)
	if err := s.snapshots.Insert(snap); err != nil {
		return nil, fmt.Errorf("创建快照: %w", err)
	}
	return snap, nil
}

// Publish 发布草稿快照；发布前自动把既有已发布快照标记为 superseded。
// 摘要已在草稿创建时冻结，发布只固化草稿里既有的冻结摘要，
// 不再按当前实时路径重算——否则后续重新分析会改写旧草稿的结论。
func (s *Service) Publish(snapID string) (*model.ProofSnapshot, error) {
	snap, err := s.snapshots.Get(snapID)
	if err != nil {
		return nil, err
	}
	if err := s.snapshots.SupersedeAllPublished(snap.ReleaseID); err != nil {
		return nil, err
	}
	if err := snap.Publish(); err != nil {
		return nil, err
	}
	if err := s.snapshots.Update(snap); err != nil {
		return nil, err
	}
	return snap, nil
}

// Get 查询快照详情。
func (s *Service) Get(snapID string) (*model.ProofSnapshot, error) {
	return s.snapshots.Get(snapID)
}

// ListByRelease 列出发布物的全部快照。
func (s *Service) ListByRelease(releaseID string) ([]*model.ProofSnapshot, error) {
	return s.snapshots.ListByRelease(releaseID)
}

// FreezeSummary 构造冻结摘要：汇总发布物当前全部路径判定，并附例外清单。
// 该摘要随后不可变地进入快照。每次调用都返回全新摘要，
// 不在调用间共享状态——共享会让相邻发布/草稿互相串改计数，
// 也会让旧草稿的冻结结论随新分析漂移。
func (s *Service) FreezeSummary(releaseID, vulnDBVersion string) (*model.SnapshotSummary, error) {
	pathList, err := s.paths.ListByRelease(releaseID)
	if err != nil {
		return nil, err
	}
	exceptions, err := s.exceptions.ListByRelease(releaseID)
	if err != nil {
		return nil, err
	}

	summary := &model.SnapshotSummary{PerCVE: map[string]string{}, VulnDBVersion: vulnDBVersion}
	reachable := map[string]bool{}
	exempted := map[string]bool{}
	exemptedPath := map[string]bool{}
	for _, ex := range exceptions {
		exempted[ex.CVEID] = true
		exemptedPath[ex.PathID] = true
	}
	for _, p := range pathList {
		// confirmed 路径不携带原判定，按例外归属恢复语义：
		// 关联例外 → 阻断（豁免）；否则 → 可达（裁决确认）。
		status := string(p.Status)
		if status == string(model.PathConfirmed) {
			if exemptedPath[p.ID] {
				status = string(model.PathBlocked)
			} else {
				status = string(model.PathReachable)
			}
		}
		if _, ok := summary.PerCVE[p.CVEID]; !ok {
			summary.PerCVE[p.CVEID] = status
		}
		switch model.PathStatus(status) {
		case model.PathReachable:
			summary.ReachableVulns++
			reachable[p.CVEID] = true
			summary.PerCVE[p.CVEID] = "reachable"
		case model.PathBlocked:
			summary.BlockedVulns++
		case model.PathInsufficientEvidence:
			summary.InsufficientVulns++
		}
	}
	for cve := range exempted {
		if !reachable[cve] {
			summary.ExemptedVulns++
		}
	}
	summary.TotalVulns = len(summary.PerCVE)
	return summary, nil
}
