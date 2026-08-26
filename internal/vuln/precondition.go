package vuln

import (
	"fmt"
	"strings"

	"task270-sbomreach/internal/model"
)

// ConditionOp 是前置条件的比较操作符。
type ConditionOp string

const (
	OpEq ConditionOp = "eq"
	OpNe ConditionOp = "ne"
	OpIn ConditionOp = "in"
	OpGt ConditionOp = "gt"
	OpGte ConditionOp = "gte"
)

// Precondition 是一条解析后的前置条件：对部署配置中的键做比较。
// 形如 "feature.legacy_ciphers.enabled == true"。
type Precondition struct {
	Key      string
	Op       ConditionOp
	Want     string
	Raw      string
}

// ParsePrecondition 把字符串表达式解析为前置条件。
// 支持的语法：
//   - <key> == <value>        （eq）
//   - <key> != <value>        （ne）
//   - <key> in <v1,v2,...>    （in）
//   - <key> > <number>        （gt）
//   - <key> >= <number>       （gte）
//
// 值为 true/false 时按布尔处理，否则按字符串/数字处理。
func ParsePrecondition(expr string) (*Precondition, error) {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return nil, nil
	}
	for _, token := range []struct {
		op  ConditionOp
		sym string
	}{
		{OpEq, "=="},
		{OpNe, "!="},
		{OpIn, " in "},
		{OpGte, ">="},
		{OpGt, ">"},
	} {
		idx := strings.Index(expr, token.sym)
		if idx < 0 {
			continue
		}
		key := strings.TrimSpace(expr[:idx])
		want := strings.TrimSpace(expr[idx+len(token.sym):])
		if key == "" || want == "" {
			return nil, fmt.Errorf("%w: 前置条件 %q 格式不完整",
				model.ErrInvalidArgument, expr)
		}
		return &Precondition{
			Key:  key,
			Op:   token.op,
			Want: want,
			Raw:  expr,
		}, nil
	}
	return nil, fmt.Errorf("%w: 无法解析前置条件 %q（支持 == / != / in / > / >=）",
		model.ErrInvalidArgument, expr)
}

// Eval 用部署配置求值前置条件。
// 配置缺失视为不满足（保守策略：无法证明可达即按不可达处理并记录证据不足）。
func (p *Precondition) Eval(cfg *model.DeployConfig) (bool, error) {
	value, ok := cfg.Lookup(p.Key)
	if !ok {
		return false, nil
	}
	return model.EvalComparison(value, string(p.Op), p.Want)
}

// ContradictionCheck 检查一组前置条件是否存在明显矛盾（同一键 eq 两个不同值）。
// 用于登记漏洞条件时的防御性校验。
func ContradictionCheck(exprs []string) error {
	eqValues := map[string]string{}
	for _, expr := range exprs {
		p, err := ParsePrecondition(expr)
		if err != nil {
			return err
		}
		if p == nil || p.Op != OpEq {
			continue
		}
		if prev, ok := eqValues[p.Key]; ok && prev != p.Want {
			return fmt.Errorf("%w: 键 %s 同时要求等于 %q 与 %q",
				model.ErrConditionContradiction, p.Key, prev, p.Want)
		}
		eqValues[p.Key] = p.Want
	}
	return nil
}
