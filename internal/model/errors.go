package model

import (
	"errors"
	"fmt"
	"sync/atomic"
	"time"
)

// 领域错误定义。所有业务异常都从这些哨兵错误派生，
// HTTP 层据此映射为 4xx / 5xx 响应。
var (
	// ErrNotFound 表示实体不存在。
	ErrNotFound = errors.New("not found")
	// ErrConflict 表示唯一键冲突（幂等插入失败）。
	ErrConflict = errors.New("conflict")
	// ErrInvalidArgument 表示请求参数非法。
	ErrInvalidArgument = errors.New("invalid argument")
	// ErrStateTransition 表示非法状态流转。
	ErrStateTransition = errors.New("illegal state transition")
	// ErrSealed 表示发布物已封存，禁止修改。
	ErrSealed = errors.New("release sealed")
	// ErrVersionMissing 表示版本坐标缺失。
	ErrVersionMissing = errors.New("version coordinate missing")
	// ErrCycleNotDeclared 表示调用图存在未声明的环。
	ErrCycleNotDeclared = errors.New("call cycle not declared")
	// ErrConditionContradiction 表示条件自相矛盾。
	ErrConditionContradiction = errors.New("contradictory condition")
)

// FieldError 包装字段级校验错误。
type FieldError struct {
	Field string
	Err   error
}

func (e *FieldError) Error() string {
	return fmt.Sprintf("字段 %q 必填: %v", e.Field, e.Err)
}

func (e *FieldError) Unwrap() error { return e.Err }

// ErrFieldRequired 构造“字段必填”错误。
func ErrFieldRequired(field string) error {
	return &FieldError{Field: field, Err: ErrInvalidArgument}
}

// IsFieldError 判断错误是否为字段级错误。
func IsFieldError(err error) bool {
	var fe *FieldError
	return errors.As(err, &fe)
}

// IsConflictError 判断错误是否为唯一键冲突。
func IsConflictError(err error) bool {
	return errors.Is(err, ErrConflict)
}

// IsConflict 是 IsConflictError 的别名（供 service 层幂等语义使用）。
func IsConflict(err error) bool {
	return errors.Is(err, ErrConflict)
}

// IsNotFound 判断错误是否实体不存在。
func IsNotFound(err error) bool {
	return errors.Is(err, ErrNotFound)
}

// IsSealed 判断错误是否发布物已封存。
func IsSealed(err error) bool {
	return errors.Is(err, ErrSealed)
}

var idCounter atomic.Uint64

// newID 生成进程内唯一的实体 ID（前缀 + 纳秒时间戳 + 自增）。
func newID(prefix string) string {
	n := idCounter.Add(1)
	return fmt.Sprintf("%s-%d-%d", prefix, time.Now().UnixNano(), n)
}
