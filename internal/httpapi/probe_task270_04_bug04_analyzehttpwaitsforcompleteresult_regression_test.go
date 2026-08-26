package httpapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"context"

	"task270-sbomreach/internal/store"
)

func TestBug04_AnalyzeHTTPWaitsForCompleteResult(t *testing.T) {

	db, err := store.Open(filepath.Join(t.TempDir(), "h.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	h := NewServer(db).Handler()
	post := func(path, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, path, bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	rec := post("/api/releases", `{"name":"acme-webapp","version":"1.4.0"}`)
	if rec.Code != 201 {
		t.Fatalf("create %d %s", rec.Code, rec.Body.String())
	}
	var rel struct{ ID string `json:"id"` }
	if err := json.Unmarshal(rec.Body.Bytes(), &rel); err != nil {
		t.Fatal(err)
	}
	rec = post("/api/releases/"+rel.ID+"/sbom?format=minimal", `{"components":[{"purl":"pkg:golang/acme/lib-http@v2.1.0","name":"lib-http","version":"v2.1.0"},{"purl":"pkg:golang/acme/web-app@1.4.0","name":"web-app","version":"1.4.0"}]}`)
	if rec.Code != 201 {
		t.Fatalf("sbom %d %s", rec.Code, rec.Body.String())
	}
	rec = post("/api/releases/"+rel.ID+"/calls", `{"edges":[{"source":"main","target":"lib-http:HTTPRead"}]}`)
	if rec.Code != 201 {
		t.Fatalf("calls %d %s", rec.Code, rec.Body.String())
	}
	rec = post("/api/releases/"+rel.ID+"/vulns", `{"cve_id":"CVE-2024-0001","affected_purl":"pkg:golang/acme/lib-http@v2.1.0","affected_symbol":"lib-http:HTTPRead","severity":"high"}`)
	if rec.Code != 201 {
		t.Fatalf("vuln %d %s", rec.Code, rec.Body.String())
	}
	rec = post("/api/releases/"+rel.ID+"/configs", `{"entry_symbols":["main"],"conditions":{"entry.main.enabled":true}}`)
	if rec.Code != 200 {
		t.Fatalf("cfg %d %s", rec.Code, rec.Body.String())
	}
	rec = post("/api/analysis/"+rel.ID+"/run", `{}`)
	if rec.Code != 200 {
		t.Fatalf("run %d %s", rec.Code, rec.Body.String())
	}
	var result struct {
		PathCount int `json:"path_count"`
		Reachable int `json:"reachable"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.PathCount < 1 || result.Reachable < 1 {
		t.Fatalf("incomplete analyze response %+v body=%s", result, rec.Body.String())
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req := httptest.NewRequest(http.MethodPost, "/api/analysis/"+rel.ID+"/run", bytes.NewBufferString(`{}`))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(ctx)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code == 200 {
		t.Fatalf("cancelled analyze must not succeed, got %d %s", rec.Code, rec.Body.String())
	}
	req = httptest.NewRequest(http.MethodGet, "/api/analysis/"+rel.ID+"/paths", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("paths %d %s", rec.Code, rec.Body.String())
	}
	var listed struct {
		Items []struct {
			Status string `json:"status"`
		} `json:"items"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &listed); err != nil {
		t.Fatal(err)
	}
	if len(listed.Items) < 1 {
		t.Fatalf("cancelled re-analyze wiped prior paths: %+v", listed.Items)
	}

}
