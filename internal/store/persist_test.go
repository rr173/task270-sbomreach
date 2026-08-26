package store

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"task270-sbomreach/internal/model"
)

func TestOpenRestartRestoresReleaseAndComponents(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "persist.db")
	db, err := Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	rel := model.NewRelease("acme-webapp", "1.4.0", "persist")
	if err := NewReleaseStore(db).Insert(rel); err != nil {
		t.Fatalf("insert release: %v", err)
	}
	cmp := model.NewComponent(rel.ID, "pkg:golang/acme/lib-http@v2.1.0", "lib-http", "v2.1.0", "library", nil)
	added, err := NewComponentStore(db).Upsert(cmp)
	if err != nil || !added {
		t.Fatalf("upsert component added=%v err=%v", added, err)
	}
	added, err = NewComponentStore(db).Upsert(cmp)
	if err != nil {
		t.Fatalf("idempotent upsert err=%v", err)
	}
	_ = added
	if err := db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("db file missing: %v", err)
	}
	db2, err := Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer db2.Close()
	got, err := NewReleaseStore(db2).Get(rel.ID)
	if err != nil {
		t.Fatalf("get release: %v", err)
	}
	if got.Status != model.ReleaseReceiving || got.Name != "acme-webapp" {
		t.Fatalf("release restored = %+v", got)
	}
	list, err := NewComponentStore(db2).ListByRelease(rel.ID)
	if err != nil || len(list) != 1 {
		t.Fatalf("components restored n=%d err=%v", len(list), err)
	}
}

func TestReplaceByReleaseIsTransactional(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "paths.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rel := model.NewRelease("r", "1", "")
	if err := NewReleaseStore(db).Insert(rel); err != nil {
		t.Fatal(err)
	}
	ps := NewPathStore(db)
	first := model.NewReachPath(rel.ID, "v1", "CVE-1", "main", "HTTPRead")
	first.Status = model.PathReachable
	if err := ps.ReplaceByRelease(context.Background(), rel.ID, []*model.ReachPath{first}); err != nil {
		t.Fatal(err)
	}
	second := model.NewReachPath(rel.ID, "v2", "CVE-2", "main", "WeakCipher")
	second.Status = model.PathBlocked
	if err := ps.ReplaceByRelease(context.Background(), rel.ID, []*model.ReachPath{second}); err != nil {
		t.Fatal(err)
	}
	list, err := ps.ListByRelease(rel.ID)
	if err != nil || len(list) != 1 {
		t.Fatalf("n=%d err=%v", len(list), err)
	}
	if list[0].CVEID != "CVE-2" {
		t.Fatalf("expected replaced CVE-2, got %s", list[0].CVEID)
	}
}
