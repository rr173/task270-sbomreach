package httpapi

import (
	"net/http"

	"task270-sbomreach/internal/service"
)

// ComponentHandler 处理构件与 SBOM 导入相关 API。
type ComponentHandler struct {
	analysis *service.AnalysisService
}

// NewComponentHandler 构造构件处理器。
func NewComponentHandler(analysis *service.AnalysisService) *ComponentHandler {
	return &ComponentHandler{analysis: analysis}
}

// Routes 注册构件路由。
//   POST /api/releases/{id}/sbom         导入 SBOM（JSON body + ?format=&source=）
//   GET  /api/releases/{id}/components   列出构件
func (h *ComponentHandler) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/releases/", h.handle)
	return mux
}

func (h *ComponentHandler) handle(w http.ResponseWriter, r *http.Request) {
	id := idFromPath(r)
	if id == "" {
		writeJSON(w, http.StatusBadRequest, ErrorBody{Error: "missing release id", Code: "invalid_argument"})
		return
	}
	switch subPath(r) {
	case "sbom":
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, ErrorBody{Error: "method not allowed", Code: "method"})
			return
		}
		h.importSBOM(w, r, id)
	case "components":
		switch r.Method {
		case http.MethodGet:
			h.listComponents(w, id)
		default:
			writeJSON(w, http.StatusMethodNotAllowed, ErrorBody{Error: "method not allowed", Code: "method"})
		}
	default:
		writeJSON(w, http.StatusNotFound, ErrorBody{Error: "not found", Code: "not_found"})
	}
}

func (h *ComponentHandler) importSBOM(w http.ResponseWriter, r *http.Request, id string) {
	format := r.URL.Query().Get("format")
	if format == "" {
		format = "minimal"
	}
	source := r.URL.Query().Get("source")
	data, err := ioReadAllLimited(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, ErrorBody{Error: "读取 SBOM 失败: " + err.Error(), Code: "invalid_argument"})
		return
	}
	result, err := h.analysis.ImportSBOM(id, format, source, data)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, result)
}

func (h *ComponentHandler) listComponents(w http.ResponseWriter, id string) {
	items, err := h.analysis.ListComponents(id)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "count": len(items)})
}
