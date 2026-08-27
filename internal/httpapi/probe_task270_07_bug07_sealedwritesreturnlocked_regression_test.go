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

func TestBug07_SealedWritesReturnLocked(t *testing.T) {

	db, err := store.Open(filepath.Join(t.TempDir(), "s.db"))
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
	var rel struct{ ID string `json:"id"` }
	_ = json.Unmarshal(rec.Body.Bytes(), &rel)
	rec = post("/api/releases/"+rel.ID+"/sbom?format=minimal", `{"components":[{"purl":"pkg:golang/acme/lib-http@v2.1.0","name":"lib-http","version":"v2.1.0"}]}`)
	if rec.Code != 201 {
		t.Fatalf("sbom %d %s", rec.Code, rec.Body.String())
	}
	rec = post("/api/releases/"+rel.ID+"/calls", `{"edges":[{"source":"main","target":"lib-http:HTTPRead"}]}`)
	rec = post("/api/releases/"+rel.ID+"/vulns", `{"cve_id":"CVE-1","affected_purl":"pkg:golang/acme/lib-http@v2.1.0","affected_symbol":"lib-http:HTTPRead","severity":"high"}`)
	rec = post("/api/releases/"+rel.ID+"/configs", `{"entry_symbols":["main"],"conditions":{"entry.main.enabled":true}}`)
	rec = post("/api/analysis/"+rel.ID+"/run", `{}`)
	if rec.Code != 200 {
		t.Fatalf("run %d %s", rec.Code, rec.Body.String())
	}
	rec = post("/api/releases/"+rel.ID+"/snapshots", `{}`)
	if rec.Code != 201 {
		t.Fatalf("draft %d %s", rec.Code, rec.Body.String())
	}
	var snap struct{ ID string `json:"id"` }
	_ = json.Unmarshal(rec.Body.Bytes(), &snap)
	rec = post("/api/snapshots/"+snap.ID+"/publish", `{}`)
	if rec.Code != 200 {
		t.Fatalf("publish %d %s", rec.Code, rec.Body.String())
	}
	rec = post("/api/releases/"+rel.ID+"/seal", `{}`)
	if rec.Code != 200 {
		t.Fatalf("seal %d %s", rec.Code, rec.Body.String())
	}
	rec = post("/api/analysis/"+rel.ID+"/run", `{}`)
	if rec.Code != http.StatusLocked {
		t.Fatalf("resealed analyze want 423 got %d %s", rec.Code, rec.Body.String())
	}
	rec = post("/api/releases/"+rel.ID+"/snapshots", `{}`)
	if rec.Code != http.StatusLocked {
		t.Fatalf("draft after seal want 423 got %d %s", rec.Code, rec.Body.String())
	}

}
