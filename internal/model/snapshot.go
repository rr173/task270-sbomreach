package model

import (
	"fmt"
	"time"
)

// SnapshotStatus 表示证明快照的生命周期。
//
// 状态机：draft → published → superseded
//   - draft：草稿，可编辑
//   - published：已发布（不可变，冻结漏洞库版本与路径证据）
//   - superseded：被新版快照替代（原快照仍只读）
type SnapshotStatus string

const (
	SnapshotDraft      SnapshotStatus = "draft"
	SnapshotPublished  SnapshotStatus = "published"
	SnapshotSuperseded SnapshotStatus = "superseded"
)

// SnapshotSummary 是快照内的结论摘要（分析结果的可追溯快照）。
type SnapshotSummary struct {
	TotalVulns          int            `json:"total_vulns"`
	ReachableVulns      int            `json:"reachable_vulns"`
	BlockedVulns        int            `json:"blocked_vulns"`
	InsufficientVulns   int            `json:"insufficient_vulns"`
	ExemptedVulns       int            `json:"exempted_vulns"`
	PerCVE              map[string]string `json:"per_cve"`
	VulnDBVersion       string         `json:"vuln_db_version"`
	ReleaseSealed       bool           `json:"release_sealed"`
}

// ProofSnapshot 是一份不可变的漏洞可达性证明：对某发布物在某一
// 漏洞库版本下的全部可达性判定做冻结快照。
type ProofSnapshot struct {
	ID          string         `json:"id"`
	ReleaseID   string         `json:"release_id"`
	Version     int            `json:"version"`
	Status      SnapshotStatus `json:"status"`
	Summary     SnapshotSummary `json:"summary"`
	PublishedAt *time.Time     `json:"published_at,omitempty"`
	SupersededAt *time.Time    `json:"superseded_at,omitempty"`
	CreatedAt   time.Time      `json:"created_at"`
}

// NewProofSnapshot 构造草稿快照，版本号由调用方传入。
func NewProofSnapshot(releaseID string, version int, summary SnapshotSummary) *ProofSnapshot {
	return &ProofSnapshot{
		ID:        newID("snap"),
		ReleaseID: releaseID,
		Version:   version,
		Status:    SnapshotDraft,
		Summary:   summary,
		CreatedAt: time.Now().UTC(),
	}
}

// Publish 发布快照（草稿 → 已发布，此后不可修改）。
func (s *ProofSnapshot) Publish() error {
	if s.Status != SnapshotDraft {
		return fmt.Errorf("%w: 快照状态 %s 不可发布", ErrStateTransition, s.Status)
	}
	now := time.Now().UTC()
	s.Status = SnapshotPublished
	s.PublishedAt = &now
	return nil
}

// Supersede 将已发布快照标记为被替代（仍只读）。
func (s *ProofSnapshot) Supersede() error {
	if s.Status != SnapshotPublished {
		return fmt.Errorf("%w: 只有已发布快照可被替代", ErrStateTransition)
	}
	now := time.Now().UTC()
	s.Status = SnapshotSuperseded
	s.SupersededAt = &now
	return nil
}

// Published 返回快照是否已发布（只读状态）。
func (s *ProofSnapshot) Published() bool {
	return s.Status == SnapshotPublished || s.Status == SnapshotSuperseded
}
