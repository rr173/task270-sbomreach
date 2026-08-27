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

// TestReplaceByReleaseWritesAllPaths 证明 ReplaceByRelease 落库全部路径，
// 而非历史上只写第一条的缺陷。
func TestReplaceByReleaseWritesAllPaths(t *testing.T) {
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
	paths := []*model.ReachPath{
		model.NewReachPath(rel.ID, "v1", "CVE-1", "main", "HTTPRead"),
		model.NewReachPath(rel.ID, "v2", "CVE-2", "main", "WeakCipher"),
		model.NewReachPath(rel.ID, "v3", "CVE-3", "main", "HiddenImport"),
	}
	paths[0].Status = model.PathReachable
	paths[1].Status = model.PathBlocked
	paths[2].Status = model.PathInsufficientEvidence
	if err := ps.ReplaceByRelease(context.Background(), rel.ID, paths); err != nil {
		t.Fatal(err)
	}
	list, err := ps.ListByRelease(rel.ID)
	if err != nil || len(list) != 3 {
		t.Fatalf("n=%d err=%v want 3", len(list), err)
	}
}

// TestReplaceByReleaseRollsBackOnInsertFailure 证明：当新路径中有一条写失败时，
// 旧路径不被清空——DELETE 与 INSERT 必须同事务回滚，不留下半成品。
func TestReplaceByReleaseRollsBackOnInsertFailure(t *testing.T) {
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
	// 先落库一条旧路径。
	old := model.NewReachPath(rel.ID, "v1", "CVE-1", "main", "HTTPRead")
	old.Status = model.PathReachable
	if err := ps.ReplaceByRelease(context.Background(), rel.ID, []*model.ReachPath{old}); err != nil {
		t.Fatal(err)
	}
	// 再尝试替换：第二条路径引用不存在的 release_id，触发外键约束失败。
	bad := model.NewReachPath("missing-release", "v2", "CVE-2", "main", "WeakCipher")
	bad.Status = model.PathBlocked
	// 第一条合法（与旧路径同 release），第二条非法。
	fresh := model.NewReachPath(rel.ID, "v3", "CVE-3", "main", "HiddenImport")
	fresh.Status = model.PathInsufficientEvidence
	if err := ps.ReplaceByRelease(context.Background(), rel.ID,
		[]*model.ReachPath{fresh, bad}); err == nil {
		t.Fatal("expected foreign-key failure on bad path, got nil")
	}
	list, err := ps.ListByRelease(rel.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].CVEID != "CVE-1" {
		t.Fatalf("old path should survive rollback, got n=%d first=%v", len(list), list)
	}
}
