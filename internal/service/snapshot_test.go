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
