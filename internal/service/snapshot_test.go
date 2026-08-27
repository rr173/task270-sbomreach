package service

import (
	"context"
	"testing"

	"task270-sbomreach/internal/model"
)

func TestPublishFreezesDraftSummaryAndSupersedes(t *testing.T) {
	rels, a, snaps, _ := testServices(t)
	id := seedAnalyzable(t, rels, a)
	if _, err := a.Analyze(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	d1, err := snaps.CreateDraft(id, "cvefeed-2026.08")
	if err != nil {
		t.Fatal(err)
	}
	if d1.Summary.ReachableVulns != 1 || d1.Summary.BlockedVulns != 1 || d1.Summary.InsufficientVulns != 1 {
		t.Fatalf("draft summary=%+v", d1.Summary)
	}
	p1, err := snaps.Publish(d1.ID)
	if err != nil {
		t.Fatal(err)
	}
	if p1.Status != model.SnapshotPublished {
		t.Fatalf("status=%s", p1.Status)
	}
	rel, err := rels.Get(id)
	if err != nil {
		t.Fatal(err)
	}
	if rel.Status != model.ReleasePublishable {
		t.Fatalf("release status=%s want publishable", rel.Status)
	}
	d2, err := snaps.CreateDraft(id, "cvefeed-2026.08")
	if err != nil {
		t.Fatal(err)
	}
	p2, err := snaps.Publish(d2.ID)
	if err != nil {
		t.Fatal(err)
	}
	if p2.Version != 2 {
		t.Fatalf("version=%d want 2", p2.Version)
	}
	old, err := snaps.Get(p1.ID)
	if err != nil {
		t.Fatal(err)
	}
	if old.Status != model.SnapshotSuperseded {
		t.Fatalf("old status=%s want superseded", old.Status)
	}
	if old.Summary.ReachableVulns != 1 {
		t.Fatalf("superseded snapshot mutated: %+v", old.Summary)
	}
}

// TestPublishFreezesDraftSummaryAcrossReanalysis 复现用户场景：
// 草稿在「弱密码特性关闭」时创建（可达1、阻断1、不足1），
// 随后打开弱密码特性并重新分析（弱密码路径变为可达），
// 再发布那份旧草稿。发布后的证明必须冻结草稿创建时的结论，
// 不应被重新分析后的新计数改写。
func TestPublishFreezesDraftSummaryAcrossReanalysis(t *testing.T) {
	rels, a, snaps, _ := testServices(t)
	id := seedAnalyzable(t, rels, a)
	if _, err := a.Analyze(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	draft, err := snaps.CreateDraft(id, "cvefeed-2026.08")
	if err != nil {
		t.Fatal(err)
	}
	if draft.Summary.ReachableVulns != 1 || draft.Summary.BlockedVulns != 1 {
		t.Fatalf("draft summary=%+v", draft.Summary)
	}
	// 打开弱密码特性并重新分析：原本被阻断的 WeakCipherInit 路径变为可达。
	cfg, err := a.LoadConfig(id)
	if err != nil {
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
	// 发布那份在旧配置下创建的草稿。
	published, err := snaps.Publish(draft.ID)
	if err != nil {
		t.Fatal(err)
	}
	// 证明必须冻结草稿创建时的结论，而非重分析后的实时计数。
	if published.Summary.ReachableVulns != 1 || published.Summary.BlockedVulns != 1 {
		t.Fatalf("published summary drifted from draft: %+v", published.Summary)
	}
	// 持久化校验：从库重新读取仍应是草稿创建时的计数。
	reloaded, err := snaps.Get(published.ID)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.Summary.ReachableVulns != 1 || reloaded.Summary.BlockedVulns != 1 {
		t.Fatalf("reloaded summary drifted from draft: %+v", reloaded.Summary)
	}
}

func TestSealRequiresPublishedSnapshot(t *testing.T) {
	rels, a, snaps, _ := testServices(t)
	id := seedAnalyzable(t, rels, a)
	if _, err := a.Analyze(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	if _, err := rels.Seal(id); err == nil {
		t.Fatal("seal without snapshot should fail")
	}
	d, err := snaps.CreateDraft(id, "cvefeed-2026.08")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := snaps.Publish(d.ID); err != nil {
		t.Fatal(err)
	}
	sealed, err := rels.Seal(id)
	if err != nil {
		t.Fatal(err)
	}
	if sealed.Status != model.ReleaseSealed {
		t.Fatalf("status=%s", sealed.Status)
	}
	if _, err := a.Analyze(context.Background(), id); err == nil {
		t.Fatal("analyze after seal should fail")
	}
}
