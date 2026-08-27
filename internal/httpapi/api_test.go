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
	// run 必须在路径落库完成之后才返回：同一响应里的计数必须与
	// 紧随其后的 paths 查询一致，不能先返回 0 再“补”出路径。
	rec = get("/api/analysis/" + rel.ID + "/paths")
	if rec.Code != http.StatusOK {
		t.Fatalf("paths %d %s", rec.Code, rec.Body.String())
	}
	var list struct {
		Count int `json:"count"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	if list.Count != result.PathCount {
		t.Fatalf("run 返回 %d 但 paths 查询为 %d：run 在落库前就返回了", result.PathCount, list.Count)
	}
	rec = get("/api/health")
	if rec.Code != http.StatusOK {
		t.Fatalf("health %d", rec.Code)
	}
}
