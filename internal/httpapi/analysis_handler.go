package httpapi

import (
	"context"
	"net/http"

	"task270-sbomreach/internal/service"
)

// AnalysisHandler 处理可达性分析运行与结果查询 API。
type AnalysisHandler struct {
	analysis *service.AnalysisService
}

// NewAnalysisHandler 构造分析处理器。
func NewAnalysisHandler(analysis *service.AnalysisService) *AnalysisHandler {
	return &AnalysisHandler{analysis: analysis}
}

// Routes 注册分析路由。
//   POST /api/analysis/{release_id}/run        运行可达性分析
//   GET  /api/analysis/{release_id}/paths      列出路径证据
//   GET  /api/analysis/{release_id}/summary    分析汇总
func (h *AnalysisHandler) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/analysis/", h.handle)
	return mux
}

func (h *AnalysisHandler) handle(w http.ResponseWriter, r *http.Request) {
	parts := splitPath(r.URL.Path)
	if len(parts) < 4 || parts[1] != "analysis" {
		writeJSON(w, http.StatusNotFound, ErrorBody{Error: "not found", Code: "not_found"})
		return
	}
	releaseID := parts[2]
	action := parts[3]
	switch action {
	case "run":
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, ErrorBody{Error: "method not allowed", Code: "method"})
			return
		}
		go func() { _, _ = h.analysis.Analyze(context.Background(), releaseID) }()
		writeJSON(w, http.StatusOK, service.AnalysisResult{ReleaseID: releaseID})
	case "paths":
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, ErrorBody{Error: "method not allowed", Code: "method"})
			return
		}
		items, err := h.analysis.ListPaths(releaseID)
		if err != nil {
			writeError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": items, "count": len(items)})
	case "summary":
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, ErrorBody{Error: "method not allowed", Code: "method"})
			return
		}
		paths, err := h.analysis.ListPaths(releaseID)
		if err != nil {
			writeError(w, err)
			return
		}
		sum := map[string]int{
			"total":       len(paths),
			"reachable":   0,
			"blocked":     0,
			"insufficient": 0,
			"confirmed":   0,
		}
		for _, p := range paths {
			switch string(p.Status) {
			case "reachable":
				sum["reachable"]++
			case "blocked":
				sum["blocked"]++
			case "insufficient_evidence":
				sum["insufficient"]++
			case "confirmed":
				sum["confirmed"]++
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"release_id": releaseID,
			"summary":    sum,
		})
	default:
		writeJSON(w, http.StatusNotFound, ErrorBody{Error: "not found", Code: "not_found"})
	}
}
