package model

import (
	"fmt"
	"time"
)

// CallEdge 表示调用摘要中的一条调用边：source 符号调用 target 符号。
// ConditionRef 引用部署配置中的条件键（可为空，表示无条件调用）。
type CallEdge struct {
	ID           string    `json:"id"`
	ReleaseID    string    `json:"release_id"`
	SourceSymbol string    `json:"source_symbol"`
	TargetSymbol string    `json:"target_symbol"`
	ConditionRef string    `json:"condition_ref,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
}

// NewCallEdge 构造调用边。
func NewCallEdge(releaseID, source, target, condRef string) *CallEdge {
	return &CallEdge{
		ID:           newID("edge"),
		ReleaseID:    releaseID,
		SourceSymbol: source,
		TargetSymbol: target,
		ConditionRef: condRef,
		CreatedAt:    time.Now().UTC(),
	}
}

// ValidateCallEdge 校验调用边的符号非空。
func ValidateCallEdge(source, target string) error {
	if source == "" {
		return ErrFieldRequired("source_symbol")
	}
	if target == "" {
		return ErrFieldRequired("target_symbol")
	}
	if source == target {
		return fmt.Errorf("%w: 自环调用 %s -> %s 必须声明为循环依赖",
			ErrInvalidArgument, source, target)
	}
	return nil
}

// EdgeKey 是调用边的唯一键（同一发布物内，源、目标、条件三元组唯一）。
func (e *CallEdge) EdgeKey() string {
	return e.SourceSymbol + ">" + e.TargetSymbol + ">" + e.ConditionRef
}
