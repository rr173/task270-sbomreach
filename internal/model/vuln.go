package model

import (
	"fmt"
	"time"
)

// Severity 表示漏洞的严重级别。
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
)

// ValidSeverity 校验严重级别取值。
func ValidSeverity(s Severity) bool {
	switch s {
	case SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow:
		return true
	default:
		return false
	}
}

// VulnCondition 是一条漏洞条件：某个构件的某个符号在满足前置条件时
// 会命中已知漏洞。AffectedPURL 标识受影响构件，AffectedSymbol 标识
// 构件内易受攻击的符号（函数/入口），Precondition 是触发的前置条件
// （引用部署配置键，可为空表示无条件触发）。
type VulnCondition struct {
	ID               string    `json:"id"`
	ReleaseID        string    `json:"release_id"`
	CVEID            string    `json:"cve_id"`
	AffectedPURL     string    `json:"affected_purl"`
	AffectedSymbol   string    `json:"affected_symbol"`
	Precondition     string    `json:"precondition,omitempty"`
	Severity         Severity  `json:"severity"`
	Description      string    `json:"description"`
	CreatedAt        time.Time `json:"created_at"`
}

// NewVulnCondition 构造漏洞条件。
func NewVulnCondition(releaseID, cveID, purl, symbol, precondition, description string, sev Severity) *VulnCondition {
	return &VulnCondition{
		ID:             newID("vuln"),
		ReleaseID:      releaseID,
		CVEID:          cveID,
		AffectedPURL:   purl,
		AffectedSymbol: symbol,
		Precondition:   precondition,
		Severity:       sev,
		Description:    description,
		CreatedAt:      time.Now().UTC(),
	}
}

// ValidateVulnCondition 校验漏洞条件字段。
func ValidateVulnCondition(cveID, purl, symbol string, sev Severity) error {
	if cveID == "" {
		return ErrFieldRequired("cve_id")
	}
	if purl == "" {
		return ErrFieldRequired("affected_purl")
	}
	if symbol == "" {
		return ErrFieldRequired("affected_symbol")
	}
	if !ValidSeverity(sev) {
		return fmt.Errorf("%w: 非法严重级别 %q", ErrInvalidArgument, sev)
	}
	return nil
}

// VulnKey 是漏洞条件的唯一键（同一发布物内 CVE + 受影响符号唯一）。
func (v *VulnCondition) VulnKey() string {
	return v.CVEID + "@" + v.AffectedSymbol
}
