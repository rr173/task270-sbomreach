package callgraph

import "testing"

func TestCyclesDetectsDirectedLoop(t *testing.T) {
	g := NewGraph()
	g.AddEdge(Edge{Source: "a", Target: "b"})
	g.AddEdge(Edge{Source: "b", Target: "c"})
	g.AddEdge(Edge{Source: "c", Target: "a"})
	g.AddEdge(Edge{Source: "a", Target: "d"})
	cycles := g.Cycles()
	if len(cycles) == 0 {
		t.Fatal("expected at least one cycle")
	}
	declared := map[string]bool{}
	g.SetCycles(cycles, declared)
	if err := g.ValidateNoUndeclaredCycle(declared); err != nil {
		t.Fatalf("declared cycles should validate: %v", err)
	}
	if err := g.ValidateNoUndeclaredCycle(map[string]bool{}); err == nil {
		t.Fatal("undeclared cycle should fail")
	}
}

func TestAddEdgeDedupesSameTriple(t *testing.T) {
	g := NewGraph()
	g.AddEdge(Edge{Source: "main", Target: "parse", ConditionRef: "feat"})
	g.AddEdge(Edge{Source: "main", Target: "parse", ConditionRef: "feat"})
	if got := len(g.Out("main")); got != 1 {
		t.Fatalf("out edges = %d, want 1", got)
	}
}
