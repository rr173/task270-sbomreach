package httpapi

// apiRouteCatalog 列出全部对外 HTTP 契约，供自检与质量门禁核对。
var apiRouteCatalog = []struct {
	method  string
	pattern string
}{
	{method: "POST", pattern: "/api/releases"},
	{method: "GET", pattern: "/api/releases"},
	{method: "GET", pattern: "/api/releases/{id}"},
	{method: "POST", pattern: "/api/releases/{id}/advance"},
	{method: "POST", pattern: "/api/releases/{id}/seal"},
	{method: "POST", pattern: "/api/releases/{id}/sbom"},
	{method: "GET", pattern: "/api/releases/{id}/components"},
	{method: "POST", pattern: "/api/releases/{id}/calls"},
	{method: "GET", pattern: "/api/releases/{id}/calls"},
	{method: "POST", pattern: "/api/releases/{id}/vulns"},
	{method: "GET", pattern: "/api/releases/{id}/vulns"},
	{method: "POST", pattern: "/api/releases/{id}/configs"},
	{method: "GET", pattern: "/api/releases/{id}/configs"},
	{method: "POST", pattern: "/api/analysis/{rid}/run"},
	{method: "GET", pattern: "/api/analysis/{rid}/paths"},
	{method: "GET", pattern: "/api/analysis/{rid}/summary"},
	{method: "POST", pattern: "/api/paths/{id}/adjudicate"},
	{method: "POST", pattern: "/api/releases/{id}/exceptions"},
	{method: "GET", pattern: "/api/releases/{id}/exceptions"},
	{method: "POST", pattern: "/api/releases/{id}/snapshots"},
	{method: "GET", pattern: "/api/releases/{id}/snapshots"},
	{method: "POST", pattern: "/api/snapshots/{id}/publish"},
	{method: "GET", pattern: "/api/snapshots/{id}"},
	{method: "GET", pattern: "/api/stats/overview"},
	{method: "GET", pattern: "/api/releases/{id}/stats"},
	{method: "GET", pattern: "/api/health"},
	{method: "GET", pattern: "/api/selfcheck"},
}
