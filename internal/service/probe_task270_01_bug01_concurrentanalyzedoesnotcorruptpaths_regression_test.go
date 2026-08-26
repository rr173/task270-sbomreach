package service

import (
	"context"
	"path/filepath"
	"testing"
	"sync"

	"task270-sbomreach/internal/model"
	"task270-sbomreach/internal/store"
)


func openSvc(t *testing.T) (*ReleaseService, *AnalysisService, *SnapshotService, *store.ComponentStore) {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	rs := store.NewReleaseStore(db)
	cs := store.NewComponentStore(db)
	es := store.NewCallEdgeStore(db)
	vs := store.NewVulnStore(db)
	cfg := store.NewConfigStore(db)
	ps := store.NewPathStore(db)
	xs := store.NewExceptionStore(db)
	im := store.NewSBOMImportStore(db)
	ss := store.NewSnapshotStore(db)
	return NewReleaseService(rs, ss), NewAnalysisService(rs, cs, es, vs, cfg, ps, xs, im, ss), NewSnapshotService(rs, ps, ss, xs), cs
}

func seedRel(t *testing.T, rels *ReleaseService, a *AnalysisService) string {
	t.Helper()
	rel, err := rels.Create("acme-webapp", "1.4.0", "probe")
	if err != nil {
		t.Fatal(err)
	}
	id := rel.ID
	sbom := `{"components":[
		{"purl":"pkg:golang/acme/web-app@1.4.0","name":"web-app","version":"1.4.0","type":"application"},
		{"purl":"pkg:golang/acme/lib-http@v2.1.0","name":"lib-http","version":"v2.1.0","type":"library"},
		{"purl":"pkg:golang/acme/lib-ssl@v3.0.0","name":"lib-ssl","version":"v3.0.0","type":"library"}
	]}`
	if _, err := a.ImportSBOM(id, "minimal", "p", []byte(sbom)); err != nil {
		t.Fatal(err)
	}
	if _, err := a.AddCallEdges(id, []struct {
		Source string `json:"source"`
		Target string `json:"target"`
		Cond   string `json:"condition_ref,omitempty"`
	}{
		{Source: "main", Target: "parseRequest"},
		{Source: "parseRequest", Target: "lib-http:HTTPRead"},
		{Source: "lib-http:HTTPRead", Target: "lib-ssl:SSLHandshake"},
		{Source: "lib-ssl:SSLHandshake", Target: "lib-ssl:WeakCipherInit", Cond: "feature.legacy_ciphers.enabled"},
		{Source: "main", Target: "healthz"},
	}); err != nil {
		t.Fatal(err)
	}
	must := func(err error) {
		if err != nil {
			t.Fatal(err)
		}
	}
	must(a.RegisterVuln(id, model.NewVulnCondition(id, "CVE-2024-0001", "pkg:golang/acme/lib-http@v2.1.0", "lib-http:HTTPRead", "", "", model.SeverityHigh)))
	must(a.RegisterVuln(id, model.NewVulnCondition(id, "CVE-2024-0002", "pkg:golang/acme/lib-ssl@v3.0.0", "lib-ssl:WeakCipherInit", "feature.legacy_ciphers.enabled == true", "", model.SeverityCritical)))
	must(a.RegisterVuln(id, model.NewVulnCondition(id, "CVE-2024-0003", "pkg:golang/acme/lib-ssl@v3.0.0", "main:hiddenImport", "", "", model.SeverityMedium)))
	cfg := model.NewDeployConfig(id)
	cfg.EntrySymbols = []string{"main"}
	must(cfg.Set("entry.main.enabled", true))
	must(cfg.Set("feature.legacy_ciphers.enabled", false))
	must(a.SaveConfig(cfg))
	return id
}


func TestBug01_ConcurrentAnalyzeDoesNotCorruptPaths(t *testing.T) {

	rels, a, _, _ := openSvc(t)
	id := seedRel(t, rels, a)
	start := make(chan struct{})
	var wg sync.WaitGroup
	errs := make(chan error, 20)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := a.Analyze(context.Background(), id)
			errs <- err
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("analyze: %v", err)
		}
	}
	paths, err := a.ListPaths(id)
	if err != nil {
		t.Fatal(err)
	}
	by := map[string]string{}
	for _, p := range paths {
		by[p.CVEID] = string(p.Status)
	}
	if by["CVE-2024-0001"] != "reachable" || by["CVE-2024-0002"] != "blocked" || by["CVE-2024-0003"] != "insufficient_evidence" {
		t.Fatalf("verdicts=%v", by)
	}

}
