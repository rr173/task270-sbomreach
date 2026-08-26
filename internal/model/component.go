package model

import (
	"fmt"
	"strings"
	"time"
)

// ComponentStatus 表示构件（SBOM 中的软件包）的可达性相关状态。
//
// 状态机：raw → resolved → vulnerable / exempted
//   - raw：已从 SBOM 导入，尚未参与调用图解析
//   - resolved：已被调用摘要引用，参与了调用图构建
//   - vulnerable：存在命中其符号的漏洞条件，进入可达性分析视野
//   - exempted：被登记为不可达例外（风险豁免），不再触发告警
type ComponentStatus string

const (
	ComponentRaw       ComponentStatus = "raw"
	ComponentResolved  ComponentStatus = "resolved"
	ComponentVulnerable ComponentStatus = "vulnerable"
	ComponentExempted  ComponentStatus = "exempted"
)

// Component 是 SBOM 中的一个软件构件，通过 PURL 唯一定位。
type Component struct {
	ID             string          `json:"id"`
	ReleaseID      string          `json:"release_id"`
	PURL           string          `json:"purl"`
	Name           string          `json:"name"`
	Version        string          `json:"version"`
	Type           string          `json:"type"`
	DependsOn      []string        `json:"depends_on"`
	Status         ComponentStatus `json:"status"`
	ExemptedReason string          `json:"exempted_reason,omitempty"`
	CreatedAt      time.Time       `json:"created_at"`
	UpdatedAt      time.Time       `json:"updated_at"`
}

// NewComponent 构造构件，初始状态 raw。
func NewComponent(releaseID, purl, name, version, typ string, dependsOn []string) *Component {
	now := time.Now().UTC()
	return &Component{
		ID:        newID("cmp"),
		ReleaseID: releaseID,
		PURL:      purl,
		Name:      name,
		Version:   version,
		Type:      typ,
		DependsOn: dependsOn,
		Status:    ComponentRaw,
		CreatedAt: now,
		UpdatedAt: now,
	}
}

// ValidateComponent 校验构件字段：PURL 与版本坐标必须完整。
func ValidateComponent(purl, name, version string) error {
	if purl == "" {
		return ErrFieldRequired("purl")
	}
	if version == "" {
		return fmt.Errorf("%w: 构件 %s 缺少版本坐标 version（purl 为 %q）",
			ErrVersionMissing, name, purl)
	}
	if !strings.Contains(purl, "@") && version == "" {
		return fmt.Errorf("%w: purl %q 未内嵌版本且未提供独立版本", ErrVersionMissing, purl)
	}
	return nil
}

// MarkVulnerable 将构件置为 vulnerable。
func (c *Component) MarkVulnerable() error {
	if c.Status == ComponentSealedForbidden() {
		return fmt.Errorf("%w: 构件 %s 已豁免，不可再标记为易受影响", ErrStateTransition, c.PURL)
	}
	c.Status = ComponentVulnerable
	c.UpdatedAt = time.Now().UTC()
	return nil
}

// MarkResolved 将构件置为 resolved（已被调用摘要引用）。
func (c *Component) MarkResolved() {
	c.Status = ComponentResolved
	c.UpdatedAt = time.Now().UTC()
}

// Exempt 将构件标记为豁免，必须携带豁免理由。
func (c *Component) Exempt(reason string) error {
	if reason == "" {
		return ErrFieldRequired("exempted_reason")
	}
	c.Status = ComponentExempted
	c.ExemptedReason = reason
	c.UpdatedAt = time.Now().UTC()
	return nil
}

// ComponentSealedForbidden 是豁免状态下禁止再次流转的哨兵标记。
// 仅供 MarkVulnerable 内部使用，避免与发布物封存语义混淆。
func ComponentSealedForbidden() ComponentStatus {
	return ComponentExempted
}
