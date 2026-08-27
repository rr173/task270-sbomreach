package service

import (
	"context"
	"path/filepath"
	"testing"

	"task270-sbomreach/internal/model"
	"task270-sbomreach/internal/store"
)

func testServices(t *testing.T) (*ReleaseService, *AnalysisService, *SnapshotService, *store.ComponentStore) {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "pipe.db"))
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
	return NewReleaseService(rs, ss),
		NewAnalysisService(rs, cs, es, vs, cfg, ps, xs, im, ss),
		NewSnapshotService(rs, ps, ss, xs),
		cs
}

func seedAnalyzable(t *testing.T, rels *ReleaseService, a *AnalysisService) string {
	t.Helper()
	rel, err := rels.Create("acme-webapp", "1.4.0", "pipeline")
	if err != nil {
		t.Fatal(err)
	}
	id := rel.ID
	sbom := `{"components":[
		{"purl":"pkg:golang/acme/web-app@1.4.0","name":"web-app","version":"1.4.0","type":"application"},
		{"purl":"pkg:golang/acme/lib-http@v2.1.0","name":"lib-http","version":"v2.1.0","type":"library","depends_on":["pkg:golang/acme/lib-ssl@v3.0.0"]},
		{"purl":"pkg:golang/acme/lib-ssl@v3.0.0","name":"lib-ssl","version":"v3.0.0","type":"library"}
	]}`
	if _, err := a.ImportSBOM(id, "minimal", "t", []byte(sbom)); err != nil {
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

func TestAnalyzePersistsThreeVerdictsAndAdvances(t *testing.T) {
	rels, a, _, _ := testServices(t)
	id := seedAnalyzable(t, rels, a)
	res, err := a.Analyze(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if res.Reachable != 1 || res.Blocked != 1 || res.Insufficient != 1 {
		t.Fatalf("counts reachable=%d blocked=%d insufficient=%d", res.Reachable, res.Blocked, res.Insufficient)
	}
	got, err := rels.Get(id)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != model.ReleasePendingReview {
		t.Fatalf("status=%s want pending_review", got.Status)
	}
}

func TestAdjudicateThenExceptionExemptsComponent(t *testing.T) {
	rels, a, _, comps := testServices(t)
	id := seedAnalyzable(t, rels, a)
	if _, err := a.Analyze(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	paths, err := a.ListPaths(id)
	if err != nil {
		t.Fatal(err)
	}
	var blocked *model.ReachPath
	for _, p := range paths {
		if p.CVEID == "CVE-2024-0002" {
			blocked = p
		}
	}
	if blocked == nil {
		t.Fatal("missing blocked path")
	}
	if _, err := a.Adjudicate(blocked.ID, "eng"); err != nil {
		t.Fatal(err)
	}
	if _, err := a.RegisterException(id, blocked.ID, "CVE-2024-0002", "legacy ciphers off", "eng"); err != nil {
		t.Fatal(err)
	}
	list, err := comps.ListByRelease(id)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, c := range list {
		if c.PURL == "pkg:golang/acme/lib-ssl@v3.0.0" {
			found = true
			if c.Status != model.ComponentExempted {
				t.Fatalf("lib-ssl status=%s want exempted", c.Status)
			}
		}
	}
	if !found {
		t.Fatal("lib-ssl missing")
	}
}

// TestAnalyzeRerunReplacesPathsAtomically 证明重跑分析时旧路径被整体替换
// （而非追加，也不会因只写一条而丢失），且状态推进与路径重写作为同一次提交成功。
func TestAnalyzeRerunReplacesPathsAtomically(t *testing.T) {
	rels, a, _, _ := testServices(t)
	id := seedAnalyzable(t, rels, a)
	if _, err := a.Analyze(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	before, err := a.ListPaths(id)
	if err != nil {
		t.Fatal(err)
	}
	// 重跑：发布物已处于 pending_review，Analyze 应整体替换路径而非追加。
	if _, err := a.Analyze(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	after, err := a.ListPaths(id)
	if err != nil {
		t.Fatal(err)
	}
	// 三条证据全部落库且不重复。
	if len(after) != len(before) {
		t.Fatalf("rerun changed path count: before=%d after=%d", len(before), len(after))
	}
	got := map[string]int{}
	for _, p := range after {
		got[string(p.Status)]++
	}
	if got["reachable"] != 1 || got["blocked"] != 1 || got["insufficient_evidence"] != 1 {
		t.Fatalf("rerun verdicts=%+v want reachable/blocked/insufficient_evidence each 1", got)
	}
	rel, err := rels.Get(id)
	if err != nil {
		t.Fatal(err)
	}
	if rel.Status != model.ReleasePendingReview {
		t.Fatalf("status=%s want pending_review", rel.Status)
	}
}
