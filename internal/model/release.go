package model

import (
	"fmt"
	"time"
)

// ReleaseStatus 表示发布物的生命周期状态。
//
// 状态机：receiving → composing → pending_review → publishable → sealed
//   - receiving：接收 SBOM / 调用摘要 / 漏洞条件 / 部署配置
//   - composing：条件化调用图构建完成，等待分析
//   - pending_review：可达性分析完成，等待工程师裁决例外
//   - publishable：所有路径已裁决，可发布证明快照
//   - sealed：已封存，任何数据不可再修改，快照冻结漏洞库版本
type ReleaseStatus string

const (
	ReleaseReceiving    ReleaseStatus = "receiving"
	ReleaseComposing    ReleaseStatus = "composing"
	ReleasePendingReview ReleaseStatus = "pending_review"
	ReleasePublishable  ReleaseStatus = "publishable"
	ReleaseSealed       ReleaseStatus = "sealed"
)

// Release 是漏洞可达性分析的基本分析单元：一个待发布的软件制品
// （镜像 / 二进制包 / 部署单元），关联其 SBOM、调用摘要、漏洞条件与部署配置。
type Release struct {
	ID          string        `json:"id"`
	Name        string        `json:"name"`
	Version     string        `json:"version"`
	Description string        `json:"description"`
	Status      ReleaseStatus `json:"status"`
	CreatedAt   time.Time     `json:"created_at"`
	UpdatedAt   time.Time     `json:"updated_at"`
	SealedAt    *time.Time    `json:"sealed_at,omitempty"`
}

// NewRelease 构造一个新的发布物，初始状态为 receiving。
func NewRelease(name, version, description string) *Release {
	now := time.Now().UTC()
	return &Release{
		ID:          newID("rel"),
		Name:        name,
		Version:     version,
		Description: description,
		Status:      ReleaseReceiving,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
}

// ValidateReleaseMeta 校验发布物元数据的非空与格式约束。
func ValidateReleaseMeta(name, version string) error {
	if name == "" {
		return ErrFieldRequired("name")
	}
	if version == "" {
		return ErrFieldRequired("version")
	}
	if len(name) > 128 {
		return fmt.Errorf("%w: name 超过 128 字符", ErrInvalidArgument)
	}
	if len(version) > 64 {
		return fmt.Errorf("%w: version 超过 64 字符", ErrInvalidArgument)
	}
	return nil
}

// CanSeal 判断发布物当前是否允许封存：只有 publishable 状态可封存。
func (r *Release) CanSeal() bool {
	return r.Status == ReleasePublishable
}

// Seal 将发布物置为 sealed 并记录封存时间。
func (r *Release) Seal() error {
	if !r.CanSeal() {
		return fmt.Errorf("%w: 发布物状态 %s 不允许封存，需先进入 %s",
			ErrStateTransition, r.Status, ReleasePublishable)
	}
	now := time.Now().UTC()
	r.Status = ReleaseSealed
	r.UpdatedAt = now
	r.SealedAt = &now
	return nil
}

// Advance 按状态机把发布物推进到下一阶段，返回推进后的状态。
func (r *Release) Advance() (ReleaseStatus, error) {
	var next ReleaseStatus
	switch r.Status {
	case ReleaseReceiving:
		next = ReleaseComposing
	case ReleaseComposing:
		next = ReleasePendingReview
	case ReleasePendingReview:
		next = ReleasePublishable
	default:
		return r.Status, fmt.Errorf("%w: 发布物状态 %s 不可继续推进",
			ErrStateTransition, r.Status)
	}
	r.Status = next
	r.UpdatedAt = time.Now().UTC()
	return next, nil
}

// IsMutable 返回发布物是否仍可写入数据（sealed 后不可写）。
func (r *Release) IsMutable() bool {
	return r.Status != ReleaseSealed
}
