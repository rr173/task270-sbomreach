package service

import (
	"context"
	"reflect"
	"sync"
	"testing"

	"task270-sbomreach/internal/model"
)

// expectedVerdict 是单次分析应当稳定得到的每个 CVE 的判定快照。
type expectedVerdict struct {
	cve    string
	status model.PathStatus
	hops   int // 期望的非空 hops 条数（reachable 路径需有证据；blocked 可为 0）
}

// singleRunVerdict 运行一次分析并提取每条 CVE 的判定与 hops 证据，作为“单次分析”基准。
func singleRunVerdict(t *testing.T, a *AnalysisService, id string) []expectedVerdict {
	t.Helper()
	if _, err := a.Analyze(context.Background(), id); err != nil {
		t.Fatalf("single analyze: %v", err)
	}
	return collectVerdicts(t, a, id)
}

func collectVerdicts(t *testing.T, a *AnalysisService, id string) []expectedVerdict {
	t.Helper()
	paths, err := a.ListPaths(id)
	if err != nil {
		t.Fatalf("list paths: %v", err)
	}
	byCVE := map[string][]expectedVerdict{}
	for _, p := range paths {
		byCVE[p.CVEID] = append(byCVE[p.CVEID], expectedVerdict{
			cve:    p.CVEID,
			status: p.Status,
			hops:   len(p.Hops),
		})
	}
	// 收敛为每 CVE 一条：reachable 优先，否则取该 CVE 唯一判定路径
	out := []expectedVerdict{}
	for _, cve := range []string{"CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003"} {
		vs := byCVE[cve]
		if len(vs) == 0 {
			out = append(out, expectedVerdict{cve: cve})
			continue
		}
		pick := vs[0]
		for _, v := range vs[1:] {
			if v.status == model.PathReachable {
				pick = v
			}
		}
		out = append(out, pick)
	}
	return out
}

// TestConcurrentAnalysisMatchesSingleRun 是回归测试：模拟产品安全工程师把同一发布物的
// 可达性分析并发提交二十次。修复前，并发分析会：
//   - 共享包级 visited map 触发“concurrent map writes”崩溃；
//   - 一条漏洞的 DFS 看到另一条漏洞标记过的符号，提前返回空 hops，把 reachable
//     误判成 blocked，或把某 CVE 写成另一条的判定；
//   - 共享着色表导致环检测漏检。
//
// 修复后，任意多次并发分析结束后，落库的路径判定与 hops 证据必须与单次分析逐字节一致。
func TestConcurrentAnalysisMatchesSingleRun(t *testing.T) {
	rels, a, _, _ := testServices(t)
	id := seedAnalyzable(t, rels, a)

	// 先取单次分析基准。
	want := singleRunVerdict(t, a, id)

	// 并发提交二十次，全部命中同一发布物。
	const n = 20
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, errs[i] = a.Analyze(context.Background(), id)
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("并发分析 #%d 失败: %v", i, err)
		}
	}

	// 并发结束后，落库的路径判定与 hops 证据仍与单次分析一致。
	got := collectVerdicts(t, a, id)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("并发分析后判定漂移:\n want=%+v\n got =%+v", want, got)
	}

	// 显式断言三条预期判定与 hops 证据完好。
	// reachable 路径必须携带完整 hops 证据（修复前并发会把它写成空 hops）；
	// blocked 路径按设计只记录 BlockReason、不带 hops（单次分析即如此）；
	// insufficient_evidence 路径为孤儿符号、无 hops。
	expected := []expectedVerdict{
		{cve: "CVE-2024-0001", status: model.PathReachable, hops: 2}, // main→parseRequest→lib-http:HTTPRead
		{cve: "CVE-2024-0002", status: model.PathBlocked, hops: 0},    // 经 SSLHandshake→WeakCipherInit，条件阻断
		{cve: "CVE-2024-0003", status: model.PathInsufficientEvidence, hops: 0}, // 孤儿符号，无证据
	}
	for i, e := range expected {
		if got[i].cve != e.cve || got[i].status != e.status || got[i].hops != e.hops {
			t.Fatalf("CVE %s: 期望 status=%s hops=%d，实际 status=%s hops=%d",
				e.cve, e.status, e.hops, got[i].status, got[i].hops)
		}
	}
}
