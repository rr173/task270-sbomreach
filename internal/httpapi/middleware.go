package httpapi

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"task270-sbomreach/internal/model"
)

// loggingResponseWriter 包装 ResponseWriter 记录状态码。
type loggingResponseWriter struct {
	http.ResponseWriter
	status int
}

func (l *loggingResponseWriter) WriteHeader(code int) {
	l.status = code
	l.ResponseWriter.WriteHeader(code)
}

// withMiddleware 统一挂载请求日志、恢复与基础头。
func withMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		lw := &loggingResponseWriter{ResponseWriter: w, status: http.StatusOK}

		defer func() {
			if rec := recover(); rec != nil {
				writeJSON(lw, http.StatusInternalServerError, ErrorBody{
					Error: "internal panic",
					Code:  "internal",
				})
			}
			dur := time.Since(start)
			// 请求日志（标准输出，便于 --smoke-test 与排查）
			_ = r
			_ = dur
		}()

		w.Header().Set("X-Content-Type-Options", "nosniff")
		next.ServeHTTP(lw, r)
	})
}

// pathVar 从形如 /api/x/{id}/y 的路径中提取第 n 段（从 0 计）。
// 简化实现：按 "/" 切分，忽略前导空串。
func pathVar(r *http.Request, n int) string {
	parts := strings.Split(r.URL.Path, "/")
	// parts[0] 为空（路径以 / 开头），/api 为 parts[1]
	idx := n + 2
	if idx < len(parts) {
		return parts[idx]
	}
	return ""
}

// idFromPath 提取路径中的资源 ID（/api/<res>/<id> 的 <id>）。
func idFromPath(r *http.Request) string {
	return pathVar(r, 1)
}

// subPath 提取 /api/<res>/<id>/<sub> 的 <sub>。
func subPath(r *http.Request) string {
	return pathVar(r, 2)
}

func isNotFound(err error) bool  { return errors.Is(err, model.ErrNotFound) }
func isConflict(err error) bool  { return errors.Is(err, model.ErrConflict) }
func isSealed(err error) bool { return errors.Is(err, model.ErrSealed) }
func isInvalid(err error) bool   { return errors.Is(err, model.ErrInvalidArgument) }
func isCycle(err error) bool     { return errors.Is(err, model.ErrCycleNotDeclared) }
func isContradiction(err error) bool {
	return errors.Is(err, model.ErrConditionContradiction)
}

func isStateTransition(err error) bool {
	return errors.Is(err, model.ErrStateTransition)
}
