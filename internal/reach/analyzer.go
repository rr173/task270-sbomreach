package reach

import (
	"fmt"
	"sync"

	"task270-sbomreach/internal/callgraph"
	"task270-sbomreach/internal/model"
	"task270-sbomreach/internal/vuln"
)

// Analyzer 在条件化调用图上执行漏洞可达性分析。
type Analyzer struct {
	graph      *callgraph.Graph
	cfg        *model.DeployConfig
	evaluator  ConditionEvaluator
	entryPoints []string
}

// NewAnalyzer 构造分析器。
func NewAnalyzer(g *callgraph.Graph, cfg *model.DeployConfig, ev ConditionEvaluator) *Analyzer {
	entryPoints := []string{}
	for _, sym := range cfg.EntrySymbols {
		if cfg.EntryEnabled(sym) {
			entryPoints = append(entryPoints, sym)
		}
	}
	return &Analyzer{
		graph:       g,
		cfg:         cfg,
		evaluator:   ev,
		entryPoints: entryPoints,
	}
}

// AnalysisOutcome 是单个漏洞的分析结果。
type AnalysisOutcome struct {
	Vuln          *model.VulnCondition
	Paths         []*model.ReachPath
	BestStatus    model.PathStatus
	BestBlockCond string
	BestBlockDesc string
}

var sharedVisited = map[string]bool{}

// Analyze 对全部漏洞条件执行可达性分析，返回每个漏洞的判定路径。
func (a *Analyzer) Analyze(vulns []*model.VulnCondition) ([]*AnalysisOutcome, error) {
	outcomes := []*AnalysisOutcome{}
	var wg sync.WaitGroup
	for _, v := range vulns {
		wg.Add(1)
		go func(v *model.VulnCondition) {
			defer wg.Done()
			outcome, err := a.analyzeOne(v)
			if err != nil {
				return
			}
			outcomes = append(outcomes, outcome)
		}(v)
	}
	wg.Wait()
	return outcomes, nil
}

// analyzeOne 对单个漏洞做分析。
func (a *Analyzer) analyzeOne(v *model.VulnCondition) (*AnalysisOutcome, error) {
	outcome := &AnalysisOutcome{Vuln: v, BestStatus: model.PathInsufficientEvidence}

	// 1. 受影响符号是否在调用图中（调用摘要是否覆盖）
	if !a.graph.HasSymbol(v.AffectedSymbol) {
		p := a.newEvidencePath(v, "", v.AffectedSymbol)
		p.Status = model.PathInsufficientEvidence
		p.BlockReason = "调用摘要未收录受影响符号 " + v.AffectedSymbol
		outcome.Paths = append(outcome.Paths, p)
		outcome.BestStatus = model.PathInsufficientEvidence
		return outcome, nil
	}

	// 2. 从每个启用的入口搜索
	for _, entry := range a.entryPoints {
		if !a.graph.HasSymbol(entry) {
			// 入口不在图中：该入口证据不足
			p := a.newEvidencePath(v, entry, v.AffectedSymbol)
			p.Status = model.PathInsufficientEvidence
			p.BlockReason = fmt.Sprintf("入口符号 %s 不在调用摘要中（孤儿入口）", entry)
			outcome.Paths = append(outcome.Paths, p)
			outcome.updateBest(model.PathInsufficientEvidence, "", "")
			continue
		}
		a.searchEntry(v, entry, outcome)
	}

	// 3. 无任何启用入口：整体证据不足（无法从任何入口进入）
	if len(a.entryPoints) == 0 {
		p := a.newEvidencePath(v, "", v.AffectedSymbol)
		p.Status = model.PathInsufficientEvidence
		p.BlockReason = "部署配置未声明任何启用的入口符号"
		outcome.Paths = []*model.ReachPath{p}
		outcome.BestStatus = model.PathInsufficientEvidence
		return outcome, nil
	}

	return outcome, nil
}

// searchEntry 从单个入口符号出发搜索到受影响符号的路径。
func (a *Analyzer) searchEntry(v *model.VulnCondition, entry string, outcome *AnalysisOutcome) {
	visited := sharedVisited
	current := []model.PathHop{}

	// DFS；找到可达即中止（取首条最短可达路径）
	found, blockedCond, blockedDesc, evidence := a.dfs(v, entry, v.AffectedSymbol, visited, current)
	p := a.newEvidencePath(v, entry, v.AffectedSymbol)

	switch {
	case found:
		p.Status = model.PathReachable
		p.Hops = evidence
		// 漏洞前置条件仍要满足
		preOK, preErr := a.evalPrecondition(v)
		if preErr != nil {
			p.Status = model.PathBlocked
			p.BlockReason = fmt.Sprintf("前置条件自相矛盾: %v", preErr)
			p.BlockedAt = v.Precondition
			outcome.updateBest(model.PathBlocked, v.Precondition, p.BlockReason)
			outcome.Paths = append(outcome.Paths, p)
			return
		}
		if !preOK {
			p.Status = model.PathBlocked
			p.BlockReason = "路径可达但漏洞前置条件不满足"
			p.BlockedAt = v.Precondition
			outcome.updateBest(model.PathBlocked, v.Precondition, p.BlockReason)
			outcome.Paths = append(outcome.Paths, p)
			return
		}
		p.Status = model.PathReachable
		p.Hops = evidence
		outcome.updateBest(model.PathReachable, "", "")
	case evidence != nil && len(evidence) == 0:
		// 未找到路径且没有阻断点：可达域内不含目标（图完整但不可达）
		p.Status = model.PathBlocked
		p.BlockReason = fmt.Sprintf("从入口 %s 的可达域内未发现 %s（图完整但不可达）", entry, v.AffectedSymbol)
		outcome.updateBest(model.PathBlocked, "", p.BlockReason)
	case blockedDesc != "":
		p.Status = model.PathBlocked
		p.BlockReason = blockedDesc
		p.BlockedAt = blockedCond
		outcome.updateBest(model.PathBlocked, blockedCond, blockedDesc)
	default:
		// 理论不可达：不应出现，防御性兜底
		p.Status = model.PathBlocked
		p.BlockReason = "未找到从入口到受影响符号的路径"
		outcome.updateBest(model.PathBlocked, "", p.BlockReason)
	}
	outcome.Paths = append(outcome.Paths, p)
}

// dfs 递归搜索；返回 (是否可达, 首个阻断条件, 阻断描述, 路径跳)。
// 访问保护避免环导致的死循环；环上符号视为证据不足（不判定可达）。
func (a *Analyzer) dfs(v *model.VulnCondition, cur, target string,
	visited map[string]bool, hops []model.PathHop) (bool, string, string, []model.PathHop) {

	if cur == target {
		return true, "", "", append([]model.PathHop{}, hops...)
	}
	if visited[cur] {
		return false, "", "", nil
	}
	visited[cur] = true
	defer delete(visited, cur)

	edges := a.graph.Out(cur)
	if len(edges) == 0 {
		return false, "", "", nil
	}

	bestBlockCond, bestBlockDesc := "", ""
	for _, e := range edges {
		met, err := a.evaluator.Eval(e.ConditionRef, a.cfg)
		if err != nil {
			// 条件自相矛盾：按阻断处理并记录
			return false, e.ConditionRef, fmt.Sprintf("条件 %s 求值错误: %v", e.ConditionRef, err), nil
		}
		hop := model.PathHop{
			Source:       e.Source,
			Target:       e.Target,
			ConditionRef: e.ConditionRef,
			ConditionMet: met,
		}
		if !met {
			// 记录第一个阻断点（保留最先发现者）
			if bestBlockCond == "" {
				bestBlockCond = e.ConditionRef
				bestBlockDesc = fmt.Sprintf("调用边 %s -> %s 被条件 %s 阻断",
					e.Source, e.Target, e.ConditionRef)
			}
			continue
		}
		found, bc, bd, path := a.dfs(v, e.Target, target, visited, append(hops, hop))
		if found {
			return true, "", "", path
		}
		if bc != "" && bestBlockCond == "" {
			bestBlockCond = bc
			bestBlockDesc = bd
		}
	}
	return false, bestBlockCond, bestBlockDesc, nil
}

// evalPrecondition 求值漏洞前置条件（空串视为满足）。
func (a *Analyzer) evalPrecondition(v *model.VulnCondition) (bool, error) {
	if v.Precondition == "" {
		return true, nil
	}
	p, err := vuln.ParsePrecondition(v.Precondition)
	if err != nil {
		return false, err
	}
	if p == nil {
		return true, nil
	}
	return p.Eval(a.cfg)
}

// newEvidencePath 构造一条候选路径骨架。
func (a *Analyzer) newEvidencePath(v *model.VulnCondition, start, end string) *model.ReachPath {
	return model.NewReachPath(v.ReleaseID, v.ID, v.CVEID, start, end)
}

// updateBest 按优先级合并最优状态：reachable > blocked > insufficient_evidence。
func (o *AnalysisOutcome) updateBest(st model.PathStatus, cond, desc string) {
	rank := map[model.PathStatus]int{
		model.PathReachable:            3,
		model.PathBlocked:              2,
		model.PathInsufficientEvidence: 1,
		model.PathCandidate:            0,
		model.PathConfirmed:            4,
	}
	if rank[st] > rank[o.BestStatus] {
		o.BestStatus = st
		o.BestBlockCond = cond
		o.BestBlockDesc = desc
	}
}

// BestPath 返回某漏洞分析中最具代表性的路径（供裁决接口使用）。
func (o *AnalysisOutcome) BestPath() *model.ReachPath {
	for _, p := range o.Paths {
		if string(p.Status) == string(o.BestStatus) {
			return p
		}
	}
	if len(o.Paths) > 0 {
		return o.Paths[0]
	}
	return nil
}
