package model

import (
	"fmt"
	"time"
)

// PathStatus 表示一条可达性分析路径的判定状态。
//
// 状态机：candidate → reachable / blocked / insufficient_evidence → confirmed
//   - candidate：分析产物，待裁决
//   - reachable：存在从入口到受影响符号的路径且沿途条件全部满足
//   - blocked：路径上存在未满足的条件，漏洞不可达（记录阻断条件）
//   - insufficient_evidence：调用摘要缺失，无法确认（证据不足）
//   - confirmed：工程师裁决确认（可达或登记为例外后的终态）
type PathStatus string

const (
	PathCandidate            PathStatus = "candidate"
	PathReachable            PathStatus = "reachable"
	PathBlocked              PathStatus = "blocked"
	PathInsufficientEvidence PathStatus = "insufficient_evidence"
	PathConfirmed            PathStatus = "confirmed"
)

// PathHop 是路径上的一跳：从某符号经某条件到达下一符号。
type PathHop struct {
	Source      string `json:"source"`
	Target      string `json:"target"`
	ConditionRef string `json:"condition_ref,omitempty"`
	ConditionMet bool   `json:"condition_met"`
}

// ReachPath 是一条漏洞可达性判定路径：从启用的入口符号到漏洞受影响符号。
type ReachPath struct {
	ID            string      `json:"id"`
	ReleaseID     string      `json:"release_id"`
	VulnID        string      `json:"vuln_id"`
	CVEID         string      `json:"cve_id"`
	StartSymbol   string      `json:"start_symbol"`
	EndSymbol     string      `json:"end_symbol"`
	Status        PathStatus  `json:"status"`
	Hops          []PathHop   `json:"hops"`
	BlockReason   string      `json:"block_reason,omitempty"`
	BlockedAt     string      `json:"blocked_condition,omitempty"`
	AdjudicatedBy string      `json:"adjudicated_by,omitempty"`
	AdjudicatedAt *time.Time  `json:"adjudicated_at,omitempty"`
	CreatedAt     time.Time   `json:"created_at"`
}

// NewReachPath 构造候选路径。
func NewReachPath(releaseID, vulnID, cveID, start, end string) *ReachPath {
	return &ReachPath{
		ID:          newID("path"),
		ReleaseID:   releaseID,
		VulnID:      vulnID,
		CVEID:       cveID,
		StartSymbol: start,
		EndSymbol:   end,
		Status:      PathCandidate,
		Hops:        []PathHop{},
		CreatedAt:   time.Now().UTC(),
	}
}

// AddHop 追加一跳并记录条件满足情况。
func (p *ReachPath) AddHop(source, target, condRef string, met bool) {
	p.Hops = append(p.Hops, PathHop{
		Source:       source,
		Target:       target,
		ConditionRef: condRef,
		ConditionMet: met,
	})
}

// Confirm 将路径置为 confirmed（裁决后的终态）。
func (p *ReachPath) Confirm(adjudicator string) error {
	if p.Status != PathReachable && p.Status != PathBlocked &&
		p.Status != PathInsufficientEvidence {
		return fmt.Errorf("%w: 状态 %s 尚未完成分析，不可确认",
			ErrStateTransition, p.Status)
	}
	now := time.Now().UTC()
	p.Status = PathConfirmed
	p.AdjudicatedBy = adjudicator
	p.AdjudicatedAt = &now
	return nil
}

// Reachable 是路径是否判定为“漏洞可触发”。
func (p *ReachPath) Reachable() bool {
	return p.Status == PathReachable || p.Status == PathConfirmed
}
