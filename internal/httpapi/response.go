// Package httpapi 提供 HTTP API 层，统一以 /api 为前缀。
package httpapi

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// ErrorBody 是统一的错误响应体。
type ErrorBody struct {
	Error   string `json:"error"`
	Message string `json:"message,omitempty"`
	Code    string `json:"code,omitempty"`
}

// writeJSON 写出 JSON 响应。
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if v == nil {
		_, _ = w.Write([]byte("{}"))
		return
	}
	if err := json.NewEncoder(w).Encode(v); err != nil {
		// 编码失败（极少见）时尽量回写错误
		_, _ = w.Write([]byte(`{"error":"response encode failed"}`))
	}
}

// writeError 按领域错误映射 HTTP 状态码。
func writeError(w http.ResponseWriter, err error) {
	status, code := mapError(err)
	writeJSON(w, status, ErrorBody{
		Error:   err.Error(),
		Message: err.Error(),
		Code:    code,
	})
}

// mapError 把领域错误映射为 (HTTP 状态码, 业务码)。
func mapError(err error) (int, string) {
	if err == nil {
		return http.StatusOK, "ok"
	}
	switch {
	case isNotFound(err):
		return http.StatusNotFound, "not_found"
	case isConflict(err):
		return http.StatusConflict, "conflict"
	case isSealed(err):
		return http.StatusLocked, "sealed"
	case isInvalid(err):
		return http.StatusBadRequest, "invalid_argument"
	case isStateTransition(err):
		return http.StatusUnprocessableEntity, "illegal_state"
	case isCycle(err):
		return http.StatusUnprocessableEntity, "cycle_not_declared"
	case isContradiction(err):
		return http.StatusUnprocessableEntity, "contradictory_condition"
	default:
		return http.StatusInternalServerError, "internal"
	}
}

// decodeJSON 解析请求体 JSON 到目标结构。
func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	if r.Body == nil {
		writeJSON(w, http.StatusBadRequest, ErrorBody{Error: "empty body", Code: "invalid_argument"})
		return false
	}
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(dst); err != nil {
		writeJSON(w, http.StatusBadRequest, ErrorBody{
			Error:   fmt.Sprintf("JSON 解析失败: %v", err),
			Code:    "invalid_argument",
		})
		return false
	}
	return true
}
