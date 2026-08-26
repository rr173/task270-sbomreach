package httpapi

import (
	"net/http"

	"task270-sbomreach/internal/store"
)

// StatsHandler 处理统计与自检 API。
type StatsHandler struct {
	stats *store.StatsStore
}

// NewStatsHandler 构造统计处理器。
func NewStatsHandler(stats *store.StatsStore) *StatsHandler {
	return &StatsHandler{stats: stats}
}

// Routes 注册统计路由。
//   GET /api/stats/overview          全局统计
//   GET /api/releases/{id}/stats     发布物明细统计
//   GET /api/health                  健康检查
//   GET /api/selfcheck               自检（服务可用的最小探针）
func (h *StatsHandler) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/stats/", h.handleStats)
	mux.HandleFunc("/api/releases/", h.handleReleaseStats)
	mux.HandleFunc("/api/health", h.handleHealth)
	mux.HandleFunc("/api/selfcheck", h.handleSelfCheck)
	return mux
}

func (h *StatsHandler) handleStats(w http.ResponseWriter, r *http.Request) {
	parts := splitPath(r.URL.Path)
	if len(parts) < 3 || parts[2] != "overview" || r.Method != http.MethodGet {
		writeJSON(w, http.StatusNotFound, ErrorBody{Error: "not found", Code: "not_found"})
		return
	}
	overview, err := h.stats.Overview()
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, overview)
}

func (h *StatsHandler) handleReleaseStats(w http.ResponseWriter, r *http.Request) {
	id := idFromPath(r)
	if id == "" || subPath(r) != "stats" || r.Method != http.MethodGet {
		writeJSON(w, http.StatusNotFound, ErrorBody{Error: "not found", Code: "not_found"})
		return
	}
	rel, st, err := h.stats.ReleaseStats(id)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"release": rel,
		"stats":   st,
	})
}

func (h *StatsHandler) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, ErrorBody{Error: "method not allowed", Code: "method"})
		return
	}
	if _, err := h.stats.Overview(); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, ErrorBody{Error: "db unavailable", Code: "internal"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
}

func (h *StatsHandler) handleSelfCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, ErrorBody{Error: "method not allowed", Code: "method"})
		return
	}
	overview, err := h.stats.Overview()
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, ErrorBody{Error: "selfcheck failed: " + err.Error(), Code: "internal"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":    "ok",
		"releases":  overview.Releases,
		"api_count": len(apiRouteCatalog),
	})
}
