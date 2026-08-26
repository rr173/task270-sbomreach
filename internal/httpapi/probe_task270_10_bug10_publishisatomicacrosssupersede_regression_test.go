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

func TestBug10_PublishIsAtomicAcrossSupersede(t *testing.T) {

	db, err := store.Open(filepath.Join(t.TempDir(), "p.db"))
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
	get := func(path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	rec := post("/api/releases", `{"name":"acme-webapp","version":"1.4.0"}`)
	var rel struct{ ID string `json:"id"` }
	_ = json.Unmarshal(rec.Body.Bytes(), &rel)
	post("/api/releases/"+rel.ID+"/sbom?format=minimal", `{"components":[{"purl":"pkg:golang/acme/lib-http@v2.1.0","name":"lib-http","version":"v2.1.0"}]}`)
	post("/api/releases/"+rel.ID+"/calls", `{"edges":[{"source":"main","target":"lib-http:HTTPRead"}]}`)
	post("/api/releases/"+rel.ID+"/vulns", `{"cve_id":"CVE-1","affected_purl":"pkg:golang/acme/lib-http@v2.1.0","affected_symbol":"lib-http:HTTPRead","severity":"high"}`)
	post("/api/releases/"+rel.ID+"/configs", `{"entry_symbols":["main"],"conditions":{"entry.main.enabled":true}}`)
	rec = post("/api/analysis/"+rel.ID+"/run", `{}`)
	if rec.Code != 200 {
		t.Fatalf("run %d %s", rec.Code, rec.Body.String())
	}
	rec = post("/api/releases/"+rel.ID+"/snapshots", `{}`)
	var s1 struct{ ID string `json:"id"` }
	_ = json.Unmarshal(rec.Body.Bytes(), &s1)
	rec = post("/api/snapshots/"+s1.ID+"/publish", `{}`)
	if rec.Code != 200 {
		t.Fatalf("publish1 %d %s", rec.Code, rec.Body.String())
	}
	rec = post("/api/releases/"+rel.ID+"/snapshots", `{}`)
	var s2 struct{ ID string `json:"id"` }
	_ = json.Unmarshal(rec.Body.Bytes(), &s2)
	rec = post("/api/snapshots/"+s2.ID+"/publish", `{}`)
	if rec.Code != 200 {
		t.Fatalf("publish2 %d %s", rec.Code, rec.Body.String())
	}
	rec = get("/api/releases/" + rel.ID + "/snapshots")
	if rec.Code != 200 {
		t.Fatalf("list %d %s", rec.Code, rec.Body.String())
	}
	var listed struct {
		Items []struct {
			ID     string `json:"id"`
			Status string `json:"status"`
		} `json:"items"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &listed); err != nil {
		t.Fatal(err)
	}
	published := 0
	superseded := 0
	for _, it := range listed.Items {
		if it.Status == "published" {
			published++
		}
		if it.Status == "superseded" {
			superseded++
		}
	}
	if published != 1 || superseded != 1 {
		t.Fatalf("snapshot statuses published=%d superseded=%d items=%+v", published, superseded, listed.Items)
	}

}
