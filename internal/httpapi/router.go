package httpapi

import (
	"database/sql"
	"net/http"

	"task270-sbomreach/internal/service"
	"task270-sbomreach/internal/store"
)

// Server 聚合全部 API handler 并对外暴露唯一入口。
type Server struct {
	db       *sql.DB
	analysis *service.AnalysisService
	releases *service.ReleaseService
	snaps    *service.SnapshotService
	stats    *store.StatsStore
}

// NewServer 基于已打开的数据库构造 HTTP 服务。
func NewServer(db *sql.DB) *Server {
	// 仓库层
	releaseStore := store.NewReleaseStore(db)
	componentStore := store.NewComponentStore(db)
	edgeStore := store.NewCallEdgeStore(db)
	vulnStore := store.NewVulnStore(db)
	configStore := store.NewConfigStore(db)
	pathStore := store.NewPathStore(db)
	exceptionStore := store.NewExceptionStore(db)
	sbomImportStore := store.NewSBOMImportStore(db)
	snapshotStore := store.NewSnapshotStore(db)
	statsStore := store.NewStatsStore(db)

	// 服务层
	releaseService := service.NewReleaseService(releaseStore, snapshotStore)
	analysisService := service.NewAnalysisService(
		releaseStore, componentStore, edgeStore, vulnStore, configStore,
		pathStore, exceptionStore, sbomImportStore, snapshotStore,
	)
	snapshotService := service.NewSnapshotService(releaseStore, pathStore, snapshotStore, exceptionStore)

	return &Server{
		db:       db,
		analysis: analysisService,
		releases: releaseService,
		snaps:    snapshotService,
		stats:    statsStore,
	}
}

// Handler 返回挂载了全部路由与中间件的 http.Handler。
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	register := func(pattern string, h http.Handler) {
		mux.Handle(pattern, h)
	}

	register("/api/releases", NewReleaseHandler(s.releases).Routes())
	register("/api/releases/", http.StripPrefix("", s.releaseSubRouter()))
	register("/api/analysis/", NewAnalysisHandler(s.analysis).Routes())
	register("/api/snapshots/", NewSnapshotHandler(s.snaps).Routes())
	register("/api/stats/", NewStatsHandler(s.stats).Routes())
	register("/api/health", NewStatsHandler(s.stats).Routes())
	register("/api/selfcheck", NewStatsHandler(s.stats).Routes())

	return withMiddleware(mux)
}

// releaseSubRouter 把 /api/releases/{id}/... 分发给各子处理器。
// 子路由间用前缀匹配避免相互吞路径。
func (s *Server) releaseSubRouter() http.Handler {
	componentH := NewComponentHandler(s.analysis)
	vulnH := NewVulnHandler(s.analysis)
	configH := NewConfigHandler(s.analysis)
	snapH := NewSnapshotHandler(s.snaps)
	statsH := NewStatsHandler(s.stats)
	releaseH := NewReleaseHandler(s.releases)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		parts := splitPath(r.URL.Path)
		if len(parts) < 3 {
			// /api/releases/{id} 单资源
			releaseH.Routes().ServeHTTP(w, r)
			return
		}
		sub := parts[3]
		switch sub {
		case "sbom", "components":
			componentH.Routes().ServeHTTP(w, r)
		case "vulns", "calls", "exceptions":
			vulnH.Routes().ServeHTTP(w, r)
		case "configs":
			configH.Routes().ServeHTTP(w, r)
		case "snapshots":
			snapH.Routes().ServeHTTP(w, r)
		case "stats":
			statsH.Routes().ServeHTTP(w, r)
		case "advance", "seal":
			releaseH.Routes().ServeHTTP(w, r)
		default:
			releaseH.Routes().ServeHTTP(w, r)
		}
	})
}
