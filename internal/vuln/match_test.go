package vuln

import (
	"testing"

	"task270-sbomreach/internal/model"
)

func TestMatchPURLPrefixAndExact(t *testing.T) {
	c := model.NewComponent("r", "pkg:golang/acme/lib-http@v2.1.0", "lib-http", "v2.1.0", "library", nil)
	exact := model.NewVulnCondition("r", "CVE-1", "pkg:golang/acme/lib-http@v2.1.0", "lib-http:HTTPRead", "", "", model.SeverityHigh)
	prefix := model.NewVulnCondition("r", "CVE-2", "pkg:golang/acme/lib-http", "lib-http:HTTPRead", "", "", model.SeverityHigh)
	miss := model.NewVulnCondition("r", "CVE-3", "pkg:golang/acme/lib-ssl@v3.0.0", "lib-ssl:SSL", "", "", model.SeverityLow)
	if !Match(exact, c) || !Match(prefix, c) || Match(miss, c) {
		t.Fatalf("match exact=%v prefix=%v miss=%v", Match(exact, c), Match(prefix, c), Match(miss, c))
	}
}

func TestPreconditionEvalMissingIsFalse(t *testing.T) {
	cfg := model.NewDeployConfig("r")
	_ = cfg.Set("feature.legacy_ciphers.enabled", false)
	p, err := ParsePrecondition("feature.legacy_ciphers.enabled == true")
	if err != nil {
		t.Fatal(err)
	}
	ok, err := p.Eval(cfg)
	if err != nil || ok {
		t.Fatalf("expected unsatisfied, ok=%v err=%v", ok, err)
	}
	missing, err := ParsePrecondition("env.mode == prod")
	if err != nil {
		t.Fatal(err)
	}
	ok, err = missing.Eval(cfg)
	if err != nil || ok {
		t.Fatalf("missing key should be false, ok=%v err=%v", ok, err)
	}
}

func TestMarkAffectedSkipsExempted(t *testing.T) {
	c := model.NewComponent("r", "pkg:golang/acme/lib-http@v2.1.0", "lib-http", "v2.1.0", "library", nil)
	if err := c.Exempt("already waived"); err != nil {
		t.Fatal(err)
	}
	v := model.NewVulnCondition("r", "CVE-1", c.PURL, "lib-http:HTTPRead", "", "", model.SeverityHigh)
	changed := MarkAffectedComponents([]*model.VulnCondition{v}, []*model.Component{c})
	if len(changed) != 0 || c.Status != model.ComponentExempted {
		t.Fatalf("exempted component mutated: changed=%d status=%s", len(changed), c.Status)
	}
}
