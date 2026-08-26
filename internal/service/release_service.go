package service

import (
	"fmt"

	"task270-sbomreach/internal/model"
	"task270-sbomreach/internal/snapshot"
	"task270-sbomreach/internal/store"
)

// ReleaseService 编排发布物生命周期。
type ReleaseService struct {
	releases  *store.ReleaseStore
	snapshots *store.SnapshotStore
}

// NewReleaseService 构造发布物服务。
func NewReleaseService(releases *store.ReleaseStore, snapshots *store.SnapshotStore) *ReleaseService {
	return &ReleaseService{releases: releases, snapshots: snapshots}
}

// Create 创建发布物并落库。
func (s *ReleaseService) Create(name, version, description string) (*model.Release, error) {
	if err := model.ValidateReleaseMeta(name, version); err != nil {
		return nil, err
	}
	r := model.NewRelease(name, version, description)
	if err := s.releases.Insert(r); err != nil {
		return nil, fmt.Errorf("创建发布物: %w", err)
	}
	return r, nil
}

// Get 查询发布物。
func (s *ReleaseService) Get(id string) (*model.Release, error) {
	return s.releases.Get(id)
}

// List 分页列出发布物。
func (s *ReleaseService) List(limit, offset int) ([]*model.Release, error) {
	return s.releases.List(limit, offset)
}

// Advance 将发布物沿状态机推进一级：
// receiving → composing → pending_review → publishable。
func (s *ReleaseService) Advance(id string) (*model.Release, error) {
	r, err := s.releases.Get(id)
	if err != nil {
		return nil, err
	}
	if _, err := r.Advance(); err != nil {
		return nil, err
	}
	if err := s.releases.Update(r); err != nil {
		return nil, err
	}
	return r, nil
}

// Seal 封存发布物：要求至少存在一份已发布证明快照。
func (s *ReleaseService) Seal(id string) (*model.Release, error) {
	r, err := s.releases.Get(id)
	if err != nil {
		return nil, err
	}
	snaps, err := s.snapshots.ListByRelease(id)
	if err != nil {
		return nil, err
	}
	published := 0
	for _, sn := range snaps {
		if sn.Published() {
			published++
		}
	}
	if _, err := snapshot.FreezeRelease(r, published); err != nil {
		return nil, err
	}
	if err := s.releases.Update(r); err != nil {
		return nil, err
	}
	return r, nil
}

// EnsureMutable 检查发布物可写（未封存），否则返回错误。
func (s *ReleaseService) EnsureMutable(id string) (*model.Release, error) {
	r, err := s.releases.Get(id)
	if err != nil {
		return nil, err
	}
	if !r.IsMutable() {
		return nil, fmt.Errorf("%w: 发布物 %s 已封存，禁止修改",
			model.ErrSealed, r.Name)
	}
	return r, nil
}
