package store

import (
	"context"
	"path/filepath"
	"testing"

	"task270-sbomreach/internal/model"
)

// TestPathListByReleaseReturnsAllRows verifies the path query iterates every
// row (the old code only read one row and leaked the cursor).
func TestPathListByReleaseReturnsAllRows(t *testing.T) {
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
	want := []*model.ReachPath{}
	for i := 0; i < 5; i++ {
		p := model.NewReachPath(rel.ID, "v", "CVE-1", "main", "HTTPRead")
		p.Status = model.PathReachable
		if err := ps.Insert(p); err != nil {
			t.Fatal(err)
		}
		want = append(want, p)
	}
	got, err := ps.ListByRelease(rel.ID)
	if err != nil {
		t.Fatalf("ListByRelease: %v", err)
	}
	if len(got) != len(want) {
		t.Fatalf("expected %d paths, got %d", len(want), len(got))
	}
	// Repeated reads must not block: the cursor is released between calls.
	for i := 0; i < 3; i++ {
		if _, err := ps.ListByRelease(rel.ID); err != nil {
			t.Fatalf("repeat read %d: %v", i, err)
		}
	}
	// Ensure a write still succeeds right after the repeated reads (no held
	// read lock / busy cursor).
	again := model.NewReachPath(rel.ID, "v2", "CVE-2", "main", "WeakCipher")
	again.Status = model.PathBlocked
	if err := ps.ReplaceByRelease(context.Background(), rel.ID, []*model.ReachPath{again}); err != nil {
		t.Fatalf("ReplaceByRelease after reads: %v", err)
	}
}

// TestConfigSaveFailureRollsBack ensures that when an insert inside Save fails,
// the pre-existing entry symbols and condition keys are preserved rather than
// wiped to an empty config.
func TestConfigSaveFailureRollsBack(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "cfg.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rel := model.NewRelease("r", "1", "")
	if err := NewReleaseStore(db).Insert(rel); err != nil {
		t.Fatal(err)
	}
	cs := NewConfigStore(db)

	good := model.NewDeployConfig(rel.ID)
	good.EntrySymbols = []string{"main"}
	if err := good.Set("entry.main.enabled", true); err != nil {
		t.Fatal(err)
	}
	if err := good.Set("feature.legacy.enabled", false); err != nil {
		t.Fatal(err)
	}
	if err := cs.Save(good); err != nil {
		t.Fatalf("initial save: %v", err)
	}

	// A config carrying a non-scalar value fails Validate at the service layer,
	// but we want to exercise a DB-level failure inside Save. Force a constraint
	// error: duplicate entry symbol violates entry_symbols PRIMARY KEY because
	// Save deletes then re-inserts; a malformed (duplicate) symbol list triggers
	// a UNIQUE failure mid-transaction.
	bad := model.NewDeployConfig(rel.ID)
	bad.EntrySymbols = []string{"main", "main"} // duplicate -> UNIQUE violation
	if err := bad.Set("entry.main.enabled", true); err != nil {
		t.Fatal(err)
	}
	if err := cs.Save(bad); err == nil {
		t.Fatal("expected Save with duplicate symbol to fail, got nil")
	}

	// Existing entry symbols and conditions must be intact after the failed save.
	loaded, err := cs.Load(rel.ID)
	if err != nil {
		t.Fatalf("Load after failed save: %v", err)
	}
	if len(loaded.EntrySymbols) == 0 {
		t.Fatalf("entry symbols wiped by failed save: %+v", loaded)
	}
	if len(loaded.Conditions) == 0 {
		t.Fatalf("conditions wiped by failed save: %+v", loaded)
	}
	if _, ok := loaded.Conditions["feature.legacy.enabled"]; !ok {
		t.Fatalf("condition key lost after failed save: %+v", loaded.Conditions)
	}
}

// TestConfigSavePersistsEntryAndConditions guards against the old bug where Save
// returned early after deleting rows, so even a "successful" save produced an
// empty config.
func TestConfigSavePersistsEntryAndConditions(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "cfg2.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rel := model.NewRelease("r", "1", "")
	if err := NewReleaseStore(db).Insert(rel); err != nil {
		t.Fatal(err)
	}
	cs := NewConfigStore(db)
	cfg := model.NewDeployConfig(rel.ID)
	cfg.EntrySymbols = []string{"main", "parse"}
	if err := cfg.Set("entry.main.enabled", true); err != nil {
		t.Fatal(err)
	}
	if err := cfg.Set("env.mode", "prod"); err != nil {
		t.Fatal(err)
	}
	if err := cs.Save(cfg); err != nil {
		t.Fatalf("save: %v", err)
	}
	loaded, err := cs.Load(rel.ID)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(loaded.EntrySymbols) != 2 {
		t.Fatalf("expected 2 entry symbols, got %d (%+v)", len(loaded.EntrySymbols), loaded.EntrySymbols)
	}
	if len(loaded.Conditions) != 2 {
		t.Fatalf("expected 2 conditions, got %d (%+v)", len(loaded.Conditions), loaded.Conditions)
	}
	has, err := cs.HasAny(rel.ID)
	if err != nil {
		t.Fatalf("HasAny: %v", err)
	}
	if !has {
		t.Fatal("HasAny should be true after a successful save")
	}
}
