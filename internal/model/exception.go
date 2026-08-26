package model

import (
	"time"
)

// Exception 是一条不可达例外：工程师确认某条路径在给定部署配置下
// 确实不可达（或被业务风险接受），登记为豁免记录，供审计追溯。
type Exception struct {
	ID             string    `json:"id"`
	ReleaseID      string    `json:"release_id"`
	PathID         string    `json:"path_id"`
	CVEID          string    `json:"cve_id"`
	Reason         string    `json:"reason"`
	AdjudicatedBy  string    `json:"adjudicated_by"`
	CreatedAt      time.Time `json:"created_at"`
}

// NewException 构造例外记录。
func NewException(releaseID, pathID, cveID, reason, adjudicator string) *Exception {
	return &Exception{
		ID:            newID("exc"),
		ReleaseID:     releaseID,
		PathID:        pathID,
		CVEID:         cveID,
		Reason:        reason,
		AdjudicatedBy: adjudicator,
		CreatedAt:     time.Now().UTC(),
	}
}

// ValidateException 校验例外字段。
func ValidateException(pathID, reason, adjudicator string) error {
	if pathID == "" {
		return ErrFieldRequired("path_id")
	}
	if reason == "" {
		return ErrFieldRequired("reason")
	}
	if adjudicator == "" {
		return ErrFieldRequired("adjudicated_by")
	}
	return nil
}
