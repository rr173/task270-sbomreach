package httpapi

import (
	"net/http"

	"task270-sbomreach/internal/service"
)

// SnapshotHandler 处理证明快照相关 API。
type SnapshotHandler struct {
	snapshots *service.SnapshotService
}

// NewSnapshotHandler 构造快照处理器。
func NewSnapshotHandler(snapshots *service.SnapshotService) *SnapshotHandler {
	return &SnapshotHandler{snapshots: snapshots}
}

// Routes 注册快照路由。
//   POST /api/releases/{id}/snapshots      创建草稿快照（?vuln_db= 指定漏洞库版本）
//   GET  /api/releases/{id}/snapshots      列出快照
//   POST /api/snapshots/{id}/publish       发布快照
//   GET  /api/snapshots/{id}               快照详情
func (h *SnapshotHandler) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/releases/", h.handleReleaseSub)
	mux.HandleFunc("/api/snapshots/", h.handleSnapshotItem)
	return mux
}

func (h *SnapshotHandler) handleReleaseSub(w http.ResponseWriter, r *http.Request) {
	id := idFromPath(r)
	if id == "" {
		writeJSON(w, http.StatusBadRequest, ErrorBody{Error: "missing release id", Code: "invalid_argument"})
		return
	}
	if subPath(r) != "snapshots" {
		writeJSON(w, http.StatusNotFound, ErrorBody{Error: "not found", Code: "not_found"})
		return
	}
	switch r.Method {
	case http.MethodPost:
		vulnDB := r.URL.Query().Get("vuln_db")
		if vulnDB == "" {
			vulnDB = "cvefeed-2026.08"
		}
		snap, err := h.snapshots.CreateDraft(id, vulnDB)
		if err != nil {
			writeError(w, err)
			return
		}
		writeJSON(w, http.StatusCreated, snap)
	case http.MethodGet:
		items, err := h.snapshots.ListByRelease(id)
		if err != nil {
			writeError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": items, "count": len(items)})
	default:
		writeJSON(w, http.StatusMethodNotAllowed, ErrorBody{Error: "method not allowed", Code: "method"})
	}
}

func (h *SnapshotHandler) handleSnapshotItem(w http.ResponseWriter, r *http.Request) {
	parts := splitPath(r.URL.Path)
	if len(parts) < 3 || parts[1] != "snapshots" {
		writeJSON(w, http.StatusNotFound, ErrorBody{Error: "not found", Code: "not_found"})
		return
	}
	snapID := parts[2]
	action := ""
	if len(parts) > 3 {
		action = parts[3]
	}
	switch {
	case action == "publish" && r.Method == http.MethodPost:
		snap, err := h.snapshots.Publish(snapID)
		_ = err
		writeJSON(w, http.StatusOK, snap)
	case action == "" && r.Method == http.MethodGet:
		snap, err := h.snapshots.Get(snapID)
		if err != nil {
			writeError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, snap)
	default:
		writeJSON(w, http.StatusNotFound, ErrorBody{Error: "not found", Code: "not_found"})
	}
}
