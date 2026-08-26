// Package callgraph 构建发布物的条件化调用图并做环检测。
package callgraph

import (
	"fmt"

	"task270-sbomreach/internal/model"
)

// Node 是调用图节点（一个符号）。
type Node struct {
	Symbol string
}

// Edge 是调用图边，携带可选的条件引用。
type Edge struct {
	Source      string
	Target      string
	ConditionRef string
}

// Graph 是条件化调用图的邻接表表示。
// 每条出边可引用部署配置中的条件键：条件不满足则该边不可通行。
type Graph struct {
	// out 邻接表：符号 → 出边列表
	out map[string][]Edge
	// in 逆邻接表：符号 → 入边列表
	in map[string][]Edge
	// symbols 全量符号集合
	symbols map[string]bool
}

// NewGraph 构造空图。
func NewGraph() *Graph {
	return &Graph{
		out:     map[string][]Edge{},
		in:      map[string][]Edge{},
		symbols: map[string]bool{},
	}
}

// AddEdge 添加一条边；若边已存在（源/目标/条件三元组相同）则忽略。
func (g *Graph) AddEdge(e Edge) {
	if !g.symbols[e.Source] {
		g.symbols[e.Source] = true
	}
	if !g.symbols[e.Target] {
		g.symbols[e.Target] = true
	}
	if g.edgeExists(e) {
		return
	}
	g.out[e.Source] = append(g.out[e.Source], e)
	g.in[e.Target] = append(g.in[e.Target], e)
}

func (g *Graph) edgeExists(e Edge) bool {
	for _, o := range g.out[e.Source] {
		if o.Target == e.Target && o.ConditionRef == e.ConditionRef {
			return true
		}
	}
	return false
}

// Out 返回符号的出边。
func (g *Graph) Out(symbol string) []Edge {
	return g.out[symbol]
}

// Symbols 返回全部符号。
func (g *Graph) Symbols() map[string]bool {
	return g.symbols
}

// HasSymbol 判断符号是否在图中。
func (g *Graph) HasSymbol(symbol string) bool {
	return g.symbols[symbol]
}

// Cycles 检测有向图中的环（DFS 三色标记），返回环路径列表。
// 调用摘要中存在环是合法输入，但环上的可达性证据会标注为
// “未声明循环依赖”，分析时视为证据不足而非直接判可达。
func (g *Graph) Cycles() [][]string {
	const (
		white = 0
		gray  = 1
		black = 2
	)
	color := map[string]int{}
	stack := []string{}
	cycles := [][]string{}
	onStack := map[string]bool{}

	var dfs func(s string)
	dfs = func(s string) {
		color[s] = gray
		stack = append(stack, s)
		onStack[s] = true
		for _, e := range g.out[s] {
			switch color[e.Target] {
			case white:
				dfs(e.Target)
			case gray:
				// 找到环：截取栈中从 e.Target 到栈顶的部分
				start := 0
				for i, v := range stack {
					if v == e.Target {
						start = i
						break
					}
				}
				cycle := append([]string{}, stack[start:]...)
				cycle = append(cycle, e.Target)
				cycles = append(cycles, cycle)
			}
		}
		stack = stack[:len(stack)-1]
		onStack[s] = false
		color[s] = black
	}

	symbols := make([]string, 0, len(g.symbols))
	for s := range g.symbols {
		symbols = append(symbols, s)
	}
	for _, s := range symbols {
		if color[s] == white {
			dfs(s)
		}
	}
	return cycles
}

// ValidateNoUndeclaredCycle 校验调用图没有未声明的环。
// declaredCycles 由调用方从模型传入（当前实现简化为：允许存在环，
// 但要求分析前调用方已通过 SetCycles 登记，否则返回 ErrCycleNotDeclared）。
func (g *Graph) ValidateNoUndeclaredCycle(declared map[string]bool) error {
	for _, cycle := range g.Cycles() {
		key := cycleKey(cycle)
		if !declared[key] {
			return fmt.Errorf("%w: 检测到未声明调用环 %v",
				model.ErrCycleNotDeclared, cycle)
		}
	}
	return nil
}

// SetCycles 登记已声明的环（键格式见 CycleKey）。
func (g *Graph) SetCycles(cycles [][]string, declared map[string]bool) {
	for _, c := range cycles {
		declared[cycleKey(c)] = true
	}
}

// CycleKey 返回环的规范键（首尾相同的稳定串，用于环登记去重）。
func CycleKey(cycle []string) string {
	return cycleKey(cycle)
}

func cycleKey(cycle []string) string {
	// 以字典序最小旋转作为规范形式
	n := len(cycle)
	rot := make([]string, n)
	best := 0
	for i := 1; i < n; i++ {
		less := false
		for k := 0; k < n; k++ {
			a := cycle[(best+k)%n]
			b := cycle[(i+k)%n]
			if b < a {
				less = true
				break
			}
			if a < b {
				break
			}
		}
		if less {
			best = i
		}
	}
	for i := 0; i < n; i++ {
		rot[i] = cycle[(best+i)%n]
	}
	return fmt.Sprintf("%v", rot)
}
