package service

import (
	"context"
	"fmt"

	"task270-sbomreach/internal/callgraph"
	"task270-sbomreach/internal/model"
	"task270-sbomreach/internal/reach"
	"task270-sbomreach/internal/sbom"
	"task270-sbomreach/internal/snapshot"
	"task270-sbomreach/internal/store"
	"task270-sbomreach/internal/vuln"
)

// AnalysisService 编排完整的漏洞可达性分析流水线：
// 数据装载 → 调用图构建 → 构件状态标记 → 可达性分析 → 路径落库 → 状态推进。
type AnalysisService struct {
	releases     *store.ReleaseStore
	components   *store.ComponentStore
	edges        *store.CallEdgeStore
	vulns        *store.VulnStore
	configs      *store.ConfigStore
	paths        *store.PathStore
	exceptions   *store.ExceptionStore
	sbomImports  *store.SBOMImportStore
	snapshots    *store.SnapshotStore
}

// NewAnalysisService 构造分析服务。
func NewAnalysisService(
	releases *store.ReleaseStore,
	components *store.ComponentStore,
	edges *store.CallEdgeStore,
	vulns *store.VulnStore,
	configs *store.ConfigStore,
	paths *store.PathStore,
	exceptions *store.ExceptionStore,
	sbomImports *store.SBOMImportStore,
	snapshots *store.SnapshotStore,
) *AnalysisService {
	return &AnalysisService{
		releases:    releases,
		components:  components,
		edges:       edges,
		vulns:       vulns,
		configs:     configs,
		paths:       paths,
		exceptions:  exceptions,
		sbomImports: sbomImports,
		snapshots:   snapshots,
	}
}

// ImportSBOM 解析并导入 SBOM 构件。
func (s *AnalysisService) ImportSBOM(releaseID, format, source string, data []byte) (*sbom.ImportResult, error) {
	if _, err := s.ensureMutable(releaseID); err != nil {
		return nil, err
	}
	doc, err := sbom.Parse(data, format, source)
	if err != nil {
		return nil, err
	}
	importer := sbom.NewImporter(s.components, s.sbomImports)
	return importer.Import(releaseID, doc)
}

// AddCallEdges 批量导入调用摘要边。
func (s *AnalysisService) AddCallEdges(releaseID string, edges []struct {
	Source string `json:"source"`
	Target string `json:"target"`
	Cond   string `json:"condition_ref,omitempty"`
}) (int, error) {
	if _, err := s.ensureMutable(releaseID); err != nil {
		return 0, err
	}
	added := 0
	for _, e := range edges {
		if err := model.ValidateCallEdge(e.Source, e.Target); err != nil {
			return added, fmt.Errorf("调用边 %s->%s: %w", e.Source, e.Target, err)
		}
		edge := model.NewCallEdge(releaseID, e.Source, e.Target, e.Cond)
		if err := s.edges.Insert(edge); err != nil {
			if model.IsConflict(err) {
				continue // 幂等：重复边跳过
			}
			return added, err
		}
		added++
	}
	return added, nil
}

// RegisterVuln 登记漏洞条件（含前置条件矛盾校验）。
func (s *AnalysisService) RegisterVuln(releaseID string, v *model.VulnCondition) error {
	if _, err := s.ensureMutable(releaseID); err != nil {
		return err
	}
	if err := model.ValidateVulnCondition(v.CVEID, v.AffectedPURL, v.AffectedSymbol, v.Severity); err != nil {
		return err
	}
	if err := vuln.ValidatePURLFormat(v.AffectedPURL); err != nil {
		return err
	}
	if v.Precondition != "" {
		if _, err := vuln.ParsePrecondition(v.Precondition); err != nil {
			return err
		}
		if err := vuln.ContradictionCheck([]string{v.Precondition}); err != nil {
			return err
		}
	}
	v.ReleaseID = releaseID
	if err := s.vulns.Insert(v); err != nil {
		if model.IsConflict(err) {
			return fmt.Errorf("%w: 漏洞 %s@%s 已登记", model.ErrConflict, v.CVEID, v.AffectedSymbol)
		}
		return err
	}
	return nil
}

// SaveConfig 保存部署配置。
func (s *AnalysisService) SaveConfig(cfg *model.DeployConfig) error {
	if _, err := s.ensureMutable(cfg.ReleaseID); err != nil {
		return err
	}
	if err := cfg.Validate(); err != nil {
		return err
	}
	return s.configs.Save(cfg)
}

// AnalysisResult 是一次分析运行的输出摘要。
type AnalysisResult struct {
	ReleaseID   string `json:"release_id"`
	PathCount   int    `json:"path_count"`
	Reachable   int    `json:"reachable"`
	Blocked     int    `json:"blocked"`
	Insufficient int   `json:"insufficient"`
	CyclesFound int    `json:"cycles_found"`
	NewStatus   model.ReleaseStatus `json:"new_status"`
}

// Analyze 执行一次完整的可达性分析并落库路径。
// ctx 取消时不得清空旧路径或推进发布物状态。
func (s *AnalysisService) Analyze(ctx context.Context, releaseID string) (*AnalysisResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	rel, err := s.releases.Get(releaseID)
	if err != nil {
		return nil, err
	}
	if rel.Status == model.ReleaseSealed {
		return nil, fmt.Errorf("%w: 发布物 %s 已封存，禁止重新分析",
			model.ErrSealed, rel.Name)
	}

	// 1. 装载数据
	components, err := s.components.ListByRelease(releaseID)
	if err != nil {
		return nil, err
	}
	vulns, err := s.vulns.ListByRelease(releaseID)
	if err != nil {
		return nil, err
	}
	cfg, err := s.configs.Load(releaseID)
	if err != nil {
		return nil, err
	}
	if has, err := s.configs.HasAny(releaseID); err != nil {
		return nil, err
	} else if !has || len(cfg.EntrySymbols) == 0 {
		return nil, fmt.Errorf("%w: 发布物尚未保存部署配置或入口符号", model.ErrInvalidArgument)
	}

	// 2. 构建条件化调用图 + 环检测（环允许存在，但必须已声明）
	builder := callgraph.NewBuilder(s.edges)
	graph, referenced, err := builder.Build(releaseID)
	if err != nil {
		return nil, err
	}
	declared := map[string]bool{}
	cycles := graph.Cycles()
	for _, c := range cycles {
		declared[callgraph.CycleKey(c)] = true
	}
	graph.SetCycles(cycles, declared)
	if err := graph.ValidateNoUndeclaredCycle(declared); err != nil {
		// 所有检测到的环都已登记，这里理论上不会失败
		return nil, err
	}

	// 3. 标记构件状态（resolved / vulnerable）
	changed := callgraph.MarkResolved(components, referenced)
	for _, c := range changed {
		if err := s.components.UpdateStatus(c.ID, string(c.Status), c.ExemptedReason); err != nil {
			return nil, fmt.Errorf("落库构件 resolved 状态 %s: %w", c.PURL, err)
		}
	}
	hit, _ := vuln.Classify(vulns, components)
	affected := vuln.MarkAffectedComponents(hit, components)
	for _, c := range affected {
		if err := s.components.UpdateStatus(c.ID, string(c.Status), c.ExemptedReason); err != nil {
			return nil, fmt.Errorf("落库构件 vulnerable 状态 %s: %w", c.PURL, err)
		}
	}

	// 4. 可达性分析
	analyzer := reach.NewAnalyzer(graph, cfg, reach.NewConfigConditionEvaluator())
	outcomes, err := analyzer.Analyze(vulns)
	if err != nil {
		return nil, err
	}

	// 5. 事务内清空旧路径并写入新路径（先落库路径，再推进状态）
	result := &AnalysisResult{ReleaseID: releaseID, NewStatus: model.ReleasePendingReview}
	allPaths := []*model.ReachPath{}
	var persistScratch []model.PathHop
	for _, o := range outcomes {
		for _, p := range o.Paths {
			persistScratch = p.Hops
			allPaths = append(allPaths, p)
			result.PathCount++
			switch p.Status {
			case model.PathReachable:
				result.Reachable++
			case model.PathBlocked:
				result.Blocked++
			case model.PathInsufficientEvidence:
				result.Insufficient++
			}
		}
	}
	for _, p := range allPaths {
		p.Hops = persistScratch
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := s.paths.ReplaceByRelease(ctx, releaseID, allPaths); err != nil {
		return nil, fmt.Errorf("落库可达路径: %w", err)
	}
	result.CyclesFound = len(cycles)

	// 6. 推进状态到 pending_review（receiving/composing 均沿状态机推进）
	for rel.Status == model.ReleaseReceiving || rel.Status == model.ReleaseComposing {
		if _, err := rel.Advance(); err != nil {
			return nil, err
		}
	}
	if err := s.releases.Update(rel); err != nil {
		return nil, err
	}
	result.NewStatus = rel.Status
	return result, nil
}

// Adjudicate 裁决一条路径为 confirmed。
func (s *AnalysisService) Adjudicate(pathID, adjudicator string) (*model.ReachPath, error) {
	p, err := s.paths.Get(pathID)
	if err != nil {
		return nil, err
	}
	if err := p.Confirm(adjudicator); err != nil {
		return nil, err
	}
	if err := s.paths.UpdateStatus(p); err != nil {
		return nil, err
	}
	return p, nil
}

// RegisterException 登记不可达例外并同步把相关构件标记为豁免。
func (s *AnalysisService) RegisterException(releaseID, pathID, cveID, reason, adjudicator string) (*model.Exception, error) {
	if err := model.ValidateException(pathID, reason, adjudicator); err != nil {
		return nil, err
	}
	ex := model.NewException(releaseID, pathID, cveID, reason, adjudicator)
	if err := s.exceptions.Insert(ex); err != nil {
		return nil, err
	}
	// 把命中该 CVE 的构件标记为豁免（分析判定为不可达，含裁决后仍带阻断理由的 confirmed 路径）
	p, err := s.paths.Get(pathID)
	if err != nil {
		return nil, err
	}
	if pathAllowsExemption(p) {
		compList, err := s.components.ListByRelease(releaseID)
		if err != nil {
			return nil, fmt.Errorf("列举构件以登记豁免: %w", err)
		}
		vulnList, vErr := s.vulns.ListByRelease(releaseID)
		if vErr != nil {
			return nil, fmt.Errorf("列举漏洞以登记豁免: %w", vErr)
		}
		for _, c := range compList {
			for _, v := range vulnList {
				if v.CVEID == cveID && vuln.Match(v, c) {
					if err := s.components.UpdateStatus(c.ID, string(model.ComponentExempted), reason); err != nil {
						return nil, fmt.Errorf("落库构件豁免状态 %s: %w", c.PURL, err)
					}
				}
			}
		}
	}
	return ex, nil
}

// pathAllowsExemption 判断路径是否允许把对应构件登记为豁免。
// confirmed 只保留裁决标记，原判定靠 BlockReason：有阻断理由视为不可达。
func pathAllowsExemption(p *model.ReachPath) bool {
	switch p.Status {
	case model.PathBlocked, model.PathInsufficientEvidence:
		return true
	case model.PathConfirmed:
		return p.BlockReason != ""
	default:
		return false
	}
}

// ListComponents 列出发布物构件（查询视图）。
func (s *AnalysisService) ListComponents(releaseID string) ([]*model.Component, error) {
	if _, err := s.releases.Get(releaseID); err != nil {
		return nil, err
	}
	return s.components.ListByRelease(releaseID)
}

// ListVulns 列出发布物漏洞条件（查询视图）。
func (s *AnalysisService) ListVulns(releaseID string) ([]*model.VulnCondition, error) {
	if _, err := s.releases.Get(releaseID); err != nil {
		return nil, err
	}
	return s.vulns.ListByRelease(releaseID)
}

// ListEdges 列出发布物调用边（查询视图）。
func (s *AnalysisService) ListEdges(releaseID string) ([]*model.CallEdge, error) {
	if _, err := s.releases.Get(releaseID); err != nil {
		return nil, err
	}
	return s.edges.ListByRelease(releaseID)
}

// ListPaths 列出发布物可达路径（查询视图）。
func (s *AnalysisService) ListPaths(releaseID string) ([]*model.ReachPath, error) {
	if _, err := s.releases.Get(releaseID); err != nil {
		return nil, err
	}
	return s.paths.ListByRelease(releaseID)
}

// LoadConfig 读取发布物部署配置（查询视图）。
func (s *AnalysisService) LoadConfig(releaseID string) (*model.DeployConfig, error) {
	if _, err := s.releases.Get(releaseID); err != nil {
		return nil, err
	}
	return s.configs.Load(releaseID)
}

// ListExceptions 列出发布物例外记录。
func (s *AnalysisService) ListExceptions(releaseID string) ([]*model.Exception, error) {
	if _, err := s.releases.Get(releaseID); err != nil {
		return nil, err
	}
	return s.exceptions.ListByRelease(releaseID)
}

// FreezeSummary 委托快照服务构造冻结摘要。
func (s *AnalysisService) FreezeSummary(releaseID, vulnDBVersion string) (*model.SnapshotSummary, error) {
	svc := snapshot.NewService(s.snapshots, s.paths, s.exceptions)
	return svc.FreezeSummary(releaseID, vulnDBVersion)
}

func (s *AnalysisService) ensureMutable(releaseID string) (*model.Release, error) {
	rel, err := s.releases.Get(releaseID)
	if err != nil {
		return nil, err
	}
	if !rel.IsMutable() {
		return nil, fmt.Errorf("%w: 发布物 %s 已封存，禁止修改", model.ErrSealed, rel.Name)
	}
	return rel, nil
}
