package httpapi

import (
	"net/http"

	"task270-sbomreach/internal/service"
)

// ReleaseHandler 处理发布物相关 API。
type ReleaseHandler struct {
	releases *service.ReleaseService
}

// NewReleaseHandler 构造发布物处理器。
func NewReleaseHandler(releases *service.ReleaseService) *ReleaseHandler {
	return &ReleaseHandler{releases: releases}
}

// createRequest 是创建发布物的请求体。
type createRequest struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	Description string `json:"description"`
}

// Routes 注册发布物路由。
//   POST /api/releases        创建发布物
//   GET  /api/releases        列出发布物
//   GET  /api/releases/{id}   发布物详情
//   PUT  /api/releases/{id}   更新发布物元数据
//   POST /api/releases/{id}/advance  推进状态机
//   POST /api/releases/{id}/seal     封存发布物
func (h *ReleaseHandler) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/releases", h.handleListOrCreate)
	mux.HandleFunc("/api/releases/", h.handleReleaseItem)
	return mux
}

func (h *ReleaseHandler) handleListOrCreate(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.list(w, r)
	case http.MethodPost:
		h.create(w, r)
	default:
		writeJSON(w, http.StatusMethodNotAllowed, ErrorBody{Error: "method not allowed", Code: "method"})
	}
}

func (h *ReleaseHandler) create(w http.ResponseWriter, r *http.Request) {
	var req createRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	rel, err := h.releases.Create(req.Name, req.Version, req.Description)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, rel)
}

func (h *ReleaseHandler) list(w http.ResponseWriter, r *http.Request) {
	limit := 50
	offset := 0
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, ok := parseInt(v); ok && n > 0 {
			limit = n
		}
	}
	if v := r.URL.Query().Get("offset"); v != "" {
		if n, ok := parseInt(v); ok && n >= 0 {
			offset = n
		}
	}
	list, err := h.releases.List(limit, offset)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"items":   list,
		"limit":   limit,
		"offset":  offset,
		"count":   len(list),
	})
}

func (h *ReleaseHandler) handleReleaseItem(w http.ResponseWriter, r *http.Request) {
	id := idFromPath(r)
	if id == "" {
		writeJSON(w, http.StatusBadRequest, ErrorBody{Error: "missing release id", Code: "invalid_argument"})
		return
	}
	switch sub := subPath(r); sub {
	case "advance":
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, ErrorBody{Error: "method not allowed", Code: "method"})
			return
		}
		h.advance(w, id)
	case "seal":
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, ErrorBody{Error: "method not allowed", Code: "method"})
			return
		}
		h.seal(w, id)
	default:
		h.getItem(w, r, id)
	}
}

func (h *ReleaseHandler) getItem(w http.ResponseWriter, r *http.Request, id string) {
	switch r.Method {
	case http.MethodGet:
		rel, err := h.releases.Get(id)
		if err != nil {
			writeError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, rel)
	default:
		writeJSON(w, http.StatusMethodNotAllowed, ErrorBody{Error: "method not allowed", Code: "method"})
	}
}

func (h *ReleaseHandler) advance(w http.ResponseWriter, id string) {
	rel, err := h.releases.Advance(id)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, rel)
}

func (h *ReleaseHandler) seal(w http.ResponseWriter, id string) {
	rel, err := h.releases.Seal(id)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, rel)
}
