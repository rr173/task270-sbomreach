package httpapi

import (
	"net/http"

	"task270-sbomreach/internal/model"
	"task270-sbomreach/internal/service"
)

// ConfigHandler 处理部署配置相关 API。
type ConfigHandler struct {
	analysis *service.AnalysisService
}

// NewConfigHandler 构造配置处理器。
func NewConfigHandler(analysis *service.AnalysisService) *ConfigHandler {
	return &ConfigHandler{analysis: analysis}
}

// configRequest 是保存部署配置的请求体。
type configRequest struct {
	EntrySymbols []string         `json:"entry_symbols"`
	Conditions   map[string]any   `json:"conditions"`
}

// Routes 注册配置路由。
//   POST /api/releases/{id}/configs   保存（覆盖）部署配置
//   GET  /api/releases/{id}/configs   读取部署配置
func (h *ConfigHandler) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/releases/", h.handle)
	return mux
}

func (h *ConfigHandler) handle(w http.ResponseWriter, r *http.Request) {
	id := idFromPath(r)
	if id == "" {
		writeJSON(w, http.StatusBadRequest, ErrorBody{Error: "missing release id", Code: "invalid_argument"})
		return
	}
	if subPath(r) != "configs" {
		writeJSON(w, http.StatusNotFound, ErrorBody{Error: "not found", Code: "not_found"})
		return
	}
	switch r.Method {
	case http.MethodPost, http.MethodPut:
		var req configRequest
		if !decodeJSON(w, r, &req) {
			return
		}
		cfg := model.NewDeployConfig(id)
		cfg.EntrySymbols = req.EntrySymbols
		for key, value := range req.Conditions {
			if err := cfg.Set(key, value); err != nil {
				writeError(w, err)
				return
			}
		}
		// 入口符号自动生成启用键（默认 true，除非显式覆盖）
		for _, sym := range req.EntrySymbols {
			key := "entry." + sym + ".enabled"
			if _, ok := cfg.Conditions[key]; !ok {
				_ = cfg.Set(key, true)
			}
		}
		if err := h.analysis.SaveConfig(cfg); err != nil {
			writeError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, cfg)
	case http.MethodGet:
		cfg, err := h.analysis.LoadConfig(id)
		if err != nil {
			writeError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, cfg)
	default:
		writeJSON(w, http.StatusMethodNotAllowed, ErrorBody{Error: "method not allowed", Code: "method"})
	}
}
