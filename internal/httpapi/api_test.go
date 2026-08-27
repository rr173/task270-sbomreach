package httpapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"task270-sbomreach/internal/store"
)

func TestHTTPReachabilityLoop(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "http.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	srv := NewServer(db).Handler()

	post := func(path, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, path, bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)
		return rec
	}
	get := func(path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)
		return rec
	}

	rec := post("/api/releases", `{"name":"acme-webapp","version":"1.4.0","description":"http"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create release %d %s", rec.Code, rec.Body.String())
	}
	var rel struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &rel); err != nil {
		t.Fatal(err)
	}
	sbom := `{"components":[
		{"purl":"pkg:golang/acme/web-app@1.4.0","name":"web-app","version":"1.4.0","type":"application"},
		{"purl":"pkg:golang/acme/lib-http@v2.1.0","name":"lib-http","version":"v2.1.0","type":"library"},
		{"purl":"pkg:golang/acme/lib-ssl@v3.0.0","name":"lib-ssl","version":"v3.0.0","type":"library"}
	]}`
	rec = post("/api/releases/"+rel.ID+"/sbom?format=minimal&source=t", sbom)
	if rec.Code != http.StatusCreated {
		t.Fatalf("sbom %d %s", rec.Code, rec.Body.String())
	}
	rec = post("/api/releases/"+rel.ID+"/calls", `{"edges":[
		{"source":"main","target":"parseRequest"},
		{"source":"parseRequest","target":"lib-http:HTTPRead"},
		{"source":"lib-http:HTTPRead","target":"lib-ssl:SSLHandshake"},
		{"source":"lib-ssl:SSLHandshake","target":"lib-ssl:WeakCipherInit","condition_ref":"feature.legacy_ciphers.enabled"}
	]}`)
	if rec.Code != http.StatusOK && rec.Code != http.StatusCreated {
		t.Fatalf("calls %d %s", rec.Code, rec.Body.String())
	}
	rec = post("/api/releases/"+rel.ID+"/vulns", `{"cve_id":"CVE-2024-0001","affected_purl":"pkg:golang/acme/lib-http@v2.1.0","affected_symbol":"lib-http:HTTPRead","severity":"high"}`)
	if rec.Code != http.StatusOK && rec.Code != http.StatusCreated {
		t.Fatalf("vuln %d %s", rec.Code, rec.Body.String())
	}
	rec = post("/api/releases/"+rel.ID+"/configs", `{"entry_symbols":["main"],"conditions":{"entry.main.enabled":true,"feature.legacy_ciphers.enabled":false}}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("config %d %s", rec.Code, rec.Body.String())
	}
	rec = post("/api/analysis/"+rel.ID+"/run", `{}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("analyze %d %s", rec.Code, rec.Body.String())
	}
	var result struct {
		Reachable int `json:"reachable"`
		PathCount int `json:"path_count"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Reachable < 1 || result.PathCount < 1 {
		t.Fatalf("analyze result %+v", result)
	}
	rec = get("/api/analysis/" + rel.ID + "/paths")
	if rec.Code != http.StatusOK {
		t.Fatalf("paths %d %s", rec.Code, rec.Body.String())
	}
	rec = get("/api/health")
	if rec.Code != http.StatusOK {
		t.Fatalf("health %d", rec.Code)
	}
}

// TestSealedWritesMapTo423Locked 验证发布物封存后的写入操作
// （运行分析、创建证明快照草稿）在 HTTP 层映射为 423 Locked，
// 而非 500 内部错误——客户端靠该状态码停止写入。
func TestSealedWritesMapTo423Locked(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "sealed.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	srv := NewServer(db).Handler()

	post := func(path, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, path, bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)
		return rec
	}
	requireCode := func(label string, rec *httptest.ResponseRecorder, want int) {
		t.Helper()
		if rec.Code != want {
			t.Fatalf("%s: got %d %s, want %d", label, rec.Code, rec.Body.String(), want)
		}
	}

	// 构造并封存一个发布物：分析 → 草稿快照 → 发布 → 封存
	rec := post("/api/releases", `{"name":"sealed-app","version":"1.0.0","description":"x"}`)
	requireCode("create release", rec, http.StatusCreated)
	var rel struct{ ID string `json:"id"` }
	if err := json.Unmarshal(rec.Body.Bytes(), &rel); err != nil {
		t.Fatal(err)
	}
	id := rel.ID
	must2xx := func(label string, rec *httptest.ResponseRecorder) {
		t.Helper()
		if rec.Code < 200 || rec.Code >= 300 {
			t.Fatalf("%s: %d %s", label, rec.Code, rec.Body.String())
		}
	}
	must2xx("sbom", post("/api/releases/"+id+"/sbom?format=minimal&source=t", `{"components":[
		{"purl":"pkg:golang/acme/app@1.0.0","name":"app","version":"1.0.0","type":"application"},
		{"purl":"pkg:golang/acme/lib@1.0.0","name":"lib","version":"1.0.0","type":"library"}
	]}`))
	must2xx("calls", post("/api/releases/"+id+"/calls", `{"edges":[
		{"source":"main","target":"lib:sink"}
	]}`))
	must2xx("vuln", post("/api/releases/"+id+"/vulns", `{"cve_id":"CVE-2024-9000","affected_purl":"pkg:golang/acme/lib@1.0.0","affected_symbol":"lib:sink","severity":"high"}`))
	must2xx("config", post("/api/releases/"+id+"/configs", `{"entry_symbols":["main"],"conditions":{"entry.main.enabled":true}}`))
	must2xx("analyze", post("/api/analysis/"+id+"/run", `{}`))
	must2xx("draft snapshot", post("/api/releases/"+id+"/snapshots?vuln_db=cvefeed-2026.08", `{}`))

	// 发布快照以使封存可行（封存要求至少一份已发布快照）
	var draft struct{ ID string `json:"id"` }
	recDraft := post("/api/releases/"+id+"/snapshots?vuln_db=cvefeed-2026.08", `{}`)
	if err := json.Unmarshal(recDraft.Body.Bytes(), &draft); err != nil {
		t.Fatal(err)
	}
	must2xx("publish", post("/api/snapshots/"+draft.ID+"/publish", `{}`))

	// 封存发布物
	requireCode("seal", post("/api/releases/"+id+"/seal", `{}`), http.StatusOK)

	// 封存后再运行分析 → 期望 423 Locked + 业务码 sealed
	recAnalyze := post("/api/analysis/"+id+"/run", `{}`)
	requireCode("analyze after seal", recAnalyze, http.StatusLocked)
	var body ErrorBody
	if err := json.Unmarshal(recAnalyze.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Code != "sealed" {
		t.Fatalf("analyze code=%q want sealed", body.Code)
	}

	// 封存后再创建证明快照草稿 → 期望 423 Locked + 业务码 sealed
	recSnap := post("/api/releases/"+id+"/snapshots?vuln_db=cvefeed-2026.08", `{}`)
	requireCode("snapshot after seal", recSnap, http.StatusLocked)
	if err := json.Unmarshal(recSnap.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Code != "sealed" {
		t.Fatalf("snapshot code=%q want sealed", body.Code)
	}
}
