package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"task270-sbomreach/internal/model"
)

func TestBug05_RepeatedListAndSaveDoNotLeakOrEmptyConfig(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "d.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	rel := model.NewRelease("r", "1", "")
	if err := NewReleaseStore(db).Insert(rel); err != nil {
		t.Fatal(err)
	}
	p := model.NewReachPath(rel.ID, "v", "CVE-1", "main", "x")
	p.Status = model.PathReachable
	if err := NewPathStore(db).ReplaceByRelease(context.Background(), rel.ID, []*model.ReachPath{p}); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		for i := 0; i < 8; i++ {
			if _, err := NewPathStore(db).ListByRelease(rel.ID); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("list: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("ListByRelease hung, likely leaked rows")
	}
	cfg := model.NewDeployConfig(rel.ID)
	cfg.EntrySymbols = []string{"main"}
	if err := cfg.Set("entry.main.enabled", true); err != nil {
		t.Fatal(err)
	}
	_ = NewConfigStore(db).Save(cfg)
	got, err := NewConfigStore(db).Load(rel.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.EntrySymbols) != 1 {
		t.Fatalf("config emptied: %+v", got)
	}
}
