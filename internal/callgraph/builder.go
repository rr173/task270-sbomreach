package callgraph

import (
	"task270-sbomreach/internal/model"
	"task270-sbomreach/internal/store"
)

// Builder 从调用边仓库构建条件化调用图。
type Builder struct {
	edges *store.CallEdgeStore
}

// NewBuilder 构造调用图构建器。
func NewBuilder(edges *store.CallEdgeStore) *Builder {
	return &Builder{edges: edges}
}

// Build 加载某发布物的全部调用边并构建调用图。
// 同时返回引用符号集合（用于把构件标记为 resolved）。
func (b *Builder) Build(releaseID string) (*Graph, map[string]bool, error) {
	edgeList, err := b.edges.ListByRelease(releaseID)
	if err != nil {
		return nil, nil, err
	}
	g := NewGraph()
	for _, e := range edgeList {
		g.AddEdge(Edge{
			Source:       e.SourceSymbol,
			Target:       e.TargetSymbol,
			ConditionRef: e.ConditionRef,
		})
	}
	referenced, err := b.edges.CollectReferencedSymbols(releaseID)
	if err != nil {
		return nil, nil, err
	}
	return g, referenced, nil
}

// MarkResolved 把被调用摘要引用的构件标记为 resolved，返回发生变化的构件列表
// （由调用方决定是否落库）。
func MarkResolved(components []*model.Component, referenced map[string]bool) []*model.Component {
	changed := []*model.Component{}
	for _, c := range components {
		if c.Status == model.ComponentResolved || c.Status == model.ComponentVulnerable ||
			c.Status == model.ComponentExempted {
			continue
		}
		prefixes := []string{
			c.Name,
			componentPurlPackage(c.PURL),
		}
		for sym := range referenced {
			for _, p := range prefixes {
				if p != "" && symbolMatches(sym, p) {
					c.MarkResolved()
					changed = append(changed, c)
					break
				}
			}
		}
	}
	return changed
}

// componentPurlPackage 提取 purl 的包名段（pkg:type/name@version 中的 name）。
func componentPurlPackage(purl string) string {
	// 形如 pkg:golang/github.com/acme/lib-http@v2.1.0
	at := -1
	for i := len(purl) - 1; i >= 0; i-- {
		if purl[i] == '@' {
			at = i
			break
		}
	}
	if at < 0 {
		return purl
	}
	return purl[:at]
}

func symbolMatches(sym, pkg string) bool {
	// 符号以 "pkg:" 或 "pkg." 或 "pkg(" 开头即匹配
	if len(sym) < len(pkg)+1 {
		return false
	}
	if sym[:len(pkg)] != pkg {
		return false
	}
	switch sym[len(pkg)] {
	case ':', '.', '(', '#':
		return true
	default:
		return false
	}
}
