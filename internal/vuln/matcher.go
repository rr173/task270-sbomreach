// Package vuln 负责漏洞条件的管理与匹配。
package vuln

import (
	"fmt"

	"task270-sbomreach/internal/model"
)

// Match 判定漏洞条件的受影响构件是否与给定构件一致。
// 匹配依据：受影响 PURL 与构件 PURL 完全相等，或受影响 PURL 是
// 构件 PURL 的兼容前缀（同包不同构建元数据）。
func Match(v *model.VulnCondition, c *model.Component) bool {
	if v.AffectedPURL == c.PURL {
		return true
	}
	// pkg:golang/acme/lib-http 可命中 purl 为 pkg:golang/acme/lib-http@v2.1.0 的构件
	if len(v.AffectedPURL) < len(c.PURL) && c.PURL[:len(v.AffectedPURL)] == v.AffectedPURL {
		if c.PURL[len(v.AffectedPURL)] == '@' {
			return true
		}
	}
	return false
}

// Classify 把所有漏洞条件按“是否命中给定构件集”分组。
// 返回 (命中集, 未命中集)。
func Classify(conditions []*model.VulnCondition, components []*model.Component) ([]*model.VulnCondition, []*model.VulnCondition) {
	hit := []*model.VulnCondition{}
	miss := []*model.VulnCondition{}
	for _, v := range conditions {
		matched := false
		for _, c := range components {
			if Match(v, c) {
				matched = true
				break
			}
		}
		if matched {
			hit = append(hit, v)
		} else {
			miss = append(miss, v)
		}
	}
	return hit, miss
}

// MarkAffectedComponents 把命中漏洞的构件标记为 vulnerable。
// 返回发生变化的构件（由调用方落库）。
func MarkAffectedComponents(conditions []*model.VulnCondition, components []*model.Component) []*model.Component {
	changed := []*model.Component{}
	for _, v := range conditions {
		for _, c := range components {
			if c.Status == model.ComponentVulnerable || c.Status == model.ComponentExempted {
				continue
			}
			if Match(v, c) {
				if err := c.MarkVulnerable(); err == nil {
					changed = append(changed, c)
				}
			}
		}
	}
	return changed
}

// ValidatePURLFormat 校验 PURL 基本形态（pkg:type/name）。
func ValidatePURLFormat(purl string) error {
	if len(purl) < 5 || purl[:4] != "pkg:" {
		return fmt.Errorf("%w: 非法 PURL %q，应以 pkg: 开头", model.ErrInvalidArgument, purl)
	}
	return nil
}
