package model

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// ConfigValue 是部署配置项的值，支持 bool / string / float64 三种标量。
type ConfigValue struct {
	Raw any `json:"raw"`
}

// MarshalJSON 让 ConfigValue 直接序列化为原始值。
func (v ConfigValue) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.Raw)
}

// UnmarshalJSON 从原始 JSON 恢复标量值。
func (v *ConfigValue) UnmarshalJSON(b []byte) error {
	var raw any
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	v.Raw = raw
	return nil
}

// AsBool 返回布尔视图。
func (v ConfigValue) AsBool() (bool, bool) {
	b, ok := v.Raw.(bool)
	return b, ok
}

// AsString 返回字符串视图。
func (v ConfigValue) AsString() (string, bool) {
	s, ok := v.Raw.(string)
	return s, ok
}

// AsFloat 返回数值视图。
func (v ConfigValue) AsFloat() (float64, bool) {
	switch n := v.Raw.(type) {
	case float64:
		return n, true
	case json.Number:
		f, err := n.Float64()
		return f, err == nil
	default:
		return 0, false
	}
}

// DeployConfig 表示发布物的一份部署配置：
//   - EntrySymbols：实际对外暴露、被启用的入口符号列表
//   - Conditions：条件键 → 配置值（供调用边条件与漏洞前置条件引用）
//
// 配置键约定（文档对外契约）：
//   - entry.<symbol>.enabled：入口是否启用（bool）
//   - feature.<name>：特性开关（bool）
//   - env.mode：运行环境（string，如 prod / staging / test）
//   - limit.<name>：数值上限（float64）
type DeployConfig struct {
	ReleaseID    string                 `json:"release_id"`
	EntrySymbols []string               `json:"entry_symbols"`
	Conditions   map[string]ConfigValue `json:"conditions"`
	UpdatedAt    time.Time              `json:"updated_at"`
}

// NewDeployConfig 构造空配置。
func NewDeployConfig(releaseID string) *DeployConfig {
	return &DeployConfig{
		ReleaseID:  releaseID,
		Conditions: map[string]ConfigValue{},
		UpdatedAt:  time.Now().UTC(),
	}
}

// Set 写入一个条件键值。
func (d *DeployConfig) Set(key string, value any) error {
	if key == "" {
		return ErrFieldRequired("condition key")
	}
	switch value.(type) {
	case bool, string, float64, int:
		d.Conditions[key] = ConfigValue{Raw: value}
		d.UpdatedAt = time.Now().UTC()
		return nil
	default:
		return fmt.Errorf("%w: 配置值类型必须是 bool/string/float64，收到 %T",
			ErrInvalidArgument, value)
	}
}

// Lookup 读取条件键值，不存在返回 (nil, false)。
func (d *DeployConfig) Lookup(key string) (ConfigValue, bool) {
	v, ok := d.Conditions[key]
	return v, ok
}

// EntryEnabled 判断某个入口符号是否启用。
func (d *DeployConfig) EntryEnabled(symbol string) bool {
	v, ok := d.Lookup("entry." + symbol + ".enabled")
	if !ok {
		return false
	}
	b, ok := v.AsBool()
	return ok && b
}

// Validate 校验配置：入口符号必须声明启用键、条件值类型合法。
func (d *DeployConfig) Validate() error {
	seen := map[string]bool{}
	for _, s := range d.EntrySymbols {
		if s == "" {
			return fmt.Errorf("%w: 入口符号不能为空", ErrInvalidArgument)
		}
		if seen[s] {
			return fmt.Errorf("%w: 入口符号 %s 重复声明", ErrInvalidArgument, s)
		}
		seen[s] = true
	}
	for k := range d.Conditions {
		if strings.HasPrefix(k, "entry.") && strings.HasSuffix(k, ".enabled") {
			if _, ok := d.Conditions[k].AsBool(); !ok {
				return fmt.Errorf("%w: 入口启用键 %s 必须是布尔值", ErrInvalidArgument, k)
			}
		}
	}
	return nil
}

// EvalComparison 评估一个比较操作（供条件求值器复用）。
// op 支持 eq / ne / in / gt / gte。
func EvalComparison(value ConfigValue, op, want string) (bool, error) {
	switch op {
	case "eq":
		return valueAsString(value) == want, nil
	case "ne":
		return valueAsString(value) != want, nil
	case "in":
		return containsComma(want, valueAsString(value)), nil
	case "gt", "gte":
		f, ok := value.AsFloat()
		if !ok {
			return false, fmt.Errorf("%w: 数值比较需要数字配置值，收到 %v",
				ErrInvalidArgument, value.Raw)
		}
		w, err := strconv.ParseFloat(want, 64)
		if err != nil {
			return false, fmt.Errorf("%w: 比较目标 %q 不是数字", ErrInvalidArgument, want)
		}
		if op == "gt" {
			return f > w, nil
		}
		return f >= w, nil
	default:
		return false, fmt.Errorf("%w: 不支持的操作符 %q", ErrInvalidArgument, op)
	}
}

func valueAsString(v ConfigValue) string {
	switch t := v.Raw.(type) {
	case bool:
		return strconv.FormatBool(t)
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	default:
		return fmt.Sprintf("%v", v.Raw)
	}
}

func containsComma(csv, s string) bool {
	for _, part := range strings.Split(csv, ",") {
		if strings.TrimSpace(part) == s {
			return true
		}
	}
	return false
}
