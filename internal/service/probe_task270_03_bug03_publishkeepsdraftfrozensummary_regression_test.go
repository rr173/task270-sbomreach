package service

import (
	"context"
	"path/filepath"
	"testing"

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


func TestBug03_PublishKeepsDraftFrozenSummary(t *testing.T) {

	rels, a, snaps, _ := openSvc(t)
	id := seedRel(t, rels, a)
	if _, err := a.Analyze(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	d1, err := snaps.CreateDraft(id, "cvefeed-2026.08")
	if err != nil {
		t.Fatal(err)
	}
	if d1.Summary.ReachableVulns != 1 || d1.Summary.BlockedVulns != 1 {
		t.Fatalf("draft=%+v", d1.Summary)
	}
	cfg := model.NewDeployConfig(id)
	cfg.EntrySymbols = []string{"main"}
	if err := cfg.Set("entry.main.enabled", true); err != nil {
		t.Fatal(err)
	}
	if err := cfg.Set("feature.legacy_ciphers.enabled", true); err != nil {
		t.Fatal(err)
	}
	if err := a.SaveConfig(cfg); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Analyze(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	pub, err := snaps.Publish(d1.ID)
	if err != nil {
		t.Fatal(err)
	}
	if pub.Summary.ReachableVulns != 1 || pub.Summary.BlockedVulns != 1 {
		t.Fatalf("published mutated to live data: %+v", pub.Summary)
	}
	got, err := snaps.Get(d1.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Summary.ReachableVulns != 1 {
		t.Fatalf("stored snapshot mutated: %+v", got.Summary)
	}

}
