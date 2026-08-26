package reach

import (
	"testing"

	"task270-sbomreach/internal/callgraph"
	"task270-sbomreach/internal/model"
)

func seedGraph() (*callgraph.Graph, *model.DeployConfig) {
	g := callgraph.NewGraph()
	g.AddEdge(callgraph.Edge{Source: "main", Target: "parseRequest"})
	g.AddEdge(callgraph.Edge{Source: "parseRequest", Target: "lib-http:HTTPRead"})
	g.AddEdge(callgraph.Edge{Source: "lib-http:HTTPRead", Target: "lib-ssl:SSLHandshake"})
	g.AddEdge(callgraph.Edge{Source: "lib-ssl:SSLHandshake", Target: "lib-ssl:WeakCipherInit", ConditionRef: "feature.legacy_ciphers.enabled"})
	cfg := model.NewDeployConfig("rel-1")
	cfg.EntrySymbols = []string{"main"}
	_ = cfg.Set("entry.main.enabled", true)
	_ = cfg.Set("feature.legacy_ciphers.enabled", false)
	return g, cfg
}

func TestAnalyzeThreeVerdicts(t *testing.T) {
	g, cfg := seedGraph()
	a := NewAnalyzer(g, cfg, NewConfigConditionEvaluator())
	vulns := []*model.VulnCondition{
		model.NewVulnCondition("rel-1", "CVE-2024-0001", "pkg:golang/acme/lib-http@v2.1.0", "lib-http:HTTPRead", "", "", model.SeverityHigh),
		model.NewVulnCondition("rel-1", "CVE-2024-0002", "pkg:golang/acme/lib-ssl@v3.0.0", "lib-ssl:WeakCipherInit", "feature.legacy_ciphers.enabled == true", "", model.SeverityCritical),
		model.NewVulnCondition("rel-1", "CVE-2024-0003", "pkg:golang/acme/lib-ssl@v3.0.0", "main:hiddenImport", "", "", model.SeverityMedium),
	}
	out, err := a.Analyze(vulns)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]model.PathStatus{}
	for _, o := range out {
		got[o.Vuln.CVEID] = o.BestStatus
	}
	if got["CVE-2024-0001"] != model.PathReachable {
		t.Fatalf("0001=%s want reachable", got["CVE-2024-0001"])
	}
	if got["CVE-2024-0002"] != model.PathBlocked {
		t.Fatalf("0002=%s want blocked", got["CVE-2024-0002"])
	}
	if got["CVE-2024-0003"] != model.PathInsufficientEvidence {
		t.Fatalf("0003=%s want insufficient_evidence", got["CVE-2024-0003"])
	}
}

func TestConditionEdgeUnblocksWhenEnabled(t *testing.T) {
	g, cfg := seedGraph()
	_ = cfg.Set("feature.legacy_ciphers.enabled", true)
	a := NewAnalyzer(g, cfg, NewConfigConditionEvaluator())
	v := model.NewVulnCondition("rel-1", "CVE-2024-0002", "pkg:golang/acme/lib-ssl@v3.0.0", "lib-ssl:WeakCipherInit", "feature.legacy_ciphers.enabled == true", "", model.SeverityCritical)
	out, err := a.Analyze([]*model.VulnCondition{v})
	if err != nil {
		t.Fatal(err)
	}
	if out[0].BestStatus != model.PathReachable {
		t.Fatalf("status=%s want reachable", out[0].BestStatus)
	}
}
