package httpapi

import (
	"net/http"

	"task270-sbomreach/internal/model"
	"task270-sbomreach/internal/service"
)

// VulnHandler 处理漏洞条件、调用摘要与例外相关 API。
type VulnHandler struct {
	analysis *service.AnalysisService
}

// NewVulnHandler 构造漏洞处理器。
func NewVulnHandler(analysis *service.AnalysisService) *VulnHandler {
	return &VulnHandler{analysis: analysis}
}

// vulnRequest 是登记漏洞条件的请求体。
type vulnRequest struct {
	CVEID          string        `json:"cve_id"`
	AffectedPURL   string        `json:"affected_purl"`
	AffectedSymbol string        `json:"affected_symbol"`
	Precondition   string        `json:"precondition,omitempty"`
	Severity       model.Severity `json:"severity"`
	Description    string        `json:"description,omitempty"`
}

// callEdgeRequest 是调用摘要的单条边。
type callEdgeRequest struct {
	Source      string `json:"source"`
	Target      string `json:"target"`
	ConditionRef string `json:"condition_ref,omitempty"`
}

// Routes 注册漏洞相关路由。
//   POST /api/releases/{id}/vulns   登记漏洞条件
//   GET  /api/releases/{id}/vulns   列出漏洞条件
//   POST /api/releases/{id}/calls   导入调用摘要
//   GET  /api/releases/{id}/calls   列出调用边
//   POST /api/releases/{id}/exceptions  登记例外
//   GET  /api/releases/{id}/exceptions  列出例外
//   POST /api/paths/{id}/adjudicate     裁决路径
func (h *VulnHandler) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/releases/", h.handleReleaseSub)
	mux.HandleFunc("/api/paths/", h.handlePath)
	return mux
}

func (h *VulnHandler) handleReleaseSub(w http.ResponseWriter, r *http.Request) {
	id := idFromPath(r)
	if id == "" {
		writeJSON(w, http.StatusBadRequest, ErrorBody{Error: "missing release id", Code: "invalid_argument"})
		return
	}
	switch subPath(r) {
	case "vulns":
		h.handleVulns(w, r, id)
	case "calls":
		h.handleCalls(w, r, id)
	case "exceptions":
		h.handleExceptions(w, r, id)
	default:
		writeJSON(w, http.StatusNotFound, ErrorBody{Error: "not found", Code: "not_found"})
	}
}

func (h *VulnHandler) handleVulns(w http.ResponseWriter, r *http.Request, id string) {
	switch r.Method {
	case http.MethodPost:
		var req vulnRequest
		if !decodeJSON(w, r, &req) {
			return
		}
		v := model.NewVulnCondition(id, req.CVEID, req.AffectedPURL, req.AffectedSymbol,
			req.Precondition, req.Description, req.Severity)
		if err := h.analysis.RegisterVuln(id, v); err != nil {
			writeError(w, err)
			return
		}
		writeJSON(w, http.StatusCreated, v)
	case http.MethodGet:
		items, err := h.analysis.ListVulns(id)
		if err != nil {
			writeError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": items, "count": len(items)})
	default:
		writeJSON(w, http.StatusMethodNotAllowed, ErrorBody{Error: "method not allowed", Code: "method"})
	}
}

func (h *VulnHandler) handleCalls(w http.ResponseWriter, r *http.Request, id string) {
	switch r.Method {
	case http.MethodPost:
		var req struct {
			Edges []callEdgeRequest `json:"edges"`
		}
		if !decodeJSON(w, r, &req) {
			return
		}
		edges := make([]struct {
			Source string `json:"source"`
			Target string `json:"target"`
			Cond   string `json:"condition_ref,omitempty"`
		}, 0, len(req.Edges))
		for _, e := range req.Edges {
			edges = append(edges, struct {
				Source string `json:"source"`
				Target string `json:"target"`
				Cond   string `json:"condition_ref,omitempty"`
			}{Source: e.Source, Target: e.Target, Cond: e.ConditionRef})
		}
		added, err := h.analysis.AddCallEdges(id, edges)
		if err != nil {
			writeError(w, err)
			return
		}
		writeJSON(w, http.StatusCreated, map[string]any{"added": added})
	case http.MethodGet:
		items, err := h.analysis.ListEdges(id)
		if err != nil {
			writeError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": items, "count": len(items)})
	default:
		writeJSON(w, http.StatusMethodNotAllowed, ErrorBody{Error: "method not allowed", Code: "method"})
	}
}

func (h *VulnHandler) handleExceptions(w http.ResponseWriter, r *http.Request, id string) {
	switch r.Method {
	case http.MethodPost:
		var req struct {
			PathID        string `json:"path_id"`
			CVEID         string `json:"cve_id"`
			Reason        string `json:"reason"`
			AdjudicatedBy string `json:"adjudicated_by"`
		}
		if !decodeJSON(w, r, &req) {
			return
		}
		ex, _ := h.analysis.RegisterException(id, req.PathID, req.CVEID, req.Reason, req.AdjudicatedBy)
		writeJSON(w, http.StatusCreated, ex)
	case http.MethodGet:
		items, err := h.analysis.ListExceptions(id)
		if err != nil {
			writeError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": items, "count": len(items)})
	default:
		writeJSON(w, http.StatusMethodNotAllowed, ErrorBody{Error: "method not allowed", Code: "method"})
	}
}

func (h *VulnHandler) handlePath(w http.ResponseWriter, r *http.Request) {
	// 路径形如 /api/paths/{id}/adjudicate
	parts := splitPath(r.URL.Path)
	if len(parts) < 4 || parts[1] != "paths" {
		writeJSON(w, http.StatusNotFound, ErrorBody{Error: "not found", Code: "not_found"})
		return
	}
	pathID := parts[2]
	action := parts[3]
	if action != "adjudicate" || r.Method != http.MethodPost {
		writeJSON(w, http.StatusNotFound, ErrorBody{Error: "not found", Code: "not_found"})
		return
	}
	var req struct {
		AdjudicatedBy string `json:"adjudicated_by"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	p, err := h.analysis.Adjudicate(pathID, req.AdjudicatedBy)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, p)
}
