// Package reach 实现漏洞可达性分析核心：在条件化调用图上
// 从启用的入口符号搜索到漏洞受影响符号的可达路径。
package reach

import (
	"fmt"

	"task270-sbomreach/internal/model"
)

// ConditionEvaluator 对调用边条件做求值。
// 返回值语义：
//   - ok=true：条件满足（无条件边恒满足）
//   - ok=false：条件不满足，该边被阻断
//   - err!=nil：配置自相矛盾等硬错误
type ConditionEvaluator interface {
	Eval(conditionRef string, cfg *model.DeployConfig) (bool, error)
}

// ConfigConditionEvaluator 基于部署配置求值条件引用。
// 条件引用即配置键；查找不到时视为不满足（保守）。
type ConfigConditionEvaluator struct{}

// NewConfigConditionEvaluator 构造默认条件评估器。
func NewConfigConditionEvaluator() *ConfigConditionEvaluator {
	return &ConfigConditionEvaluator{}
}

// Eval 实现 ConditionEvaluator。
func (e *ConfigConditionEvaluator) Eval(conditionRef string, cfg *model.DeployConfig) (bool, error) {
	if conditionRef == "" {
		return true, nil
	}
	value, ok := cfg.Lookup(conditionRef)
	if !ok {
		return false, nil
	}
	b, ok := value.AsBool()
	if !ok {
		return false, fmt.Errorf("%w: 条件键 %s 不是布尔值（收到 %v）",
			model.ErrInvalidArgument, conditionRef, value.Raw)
	}
	return b, nil
}

// EdgeResolver 把调用图边与配置合并后交给分析器使用。
// 简化结构：分析器直接接收构建好的图 + 配置，不需要额外接口。
