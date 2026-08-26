// task270-sbomreach 是 SBOM 漏洞可达性证明服务入口。
//
// 用法：
//
//	task270-sbomreach [--addr :8080] [--db /path/to/sbomreach.db]
//	task270-sbomreach --smoke-test [--db /path/to/sbomreach.db]
package main

import (
	"context"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"task270-sbomreach/internal/httpapi"
	"task270-sbomreach/internal/model"
	"task270-sbomreach/internal/service"
	"task270-sbomreach/internal/store"
)

func main() {
	addr := flag.String("addr", ":8080", "HTTP 监听地址")
	dbPath := flag.String("db", "task270-sbomreach.db", "SQLite 数据库路径")
	smoke := flag.Bool("smoke-test", false, "运行端到端冒烟测试后退出（0 表示通过）")
	flag.Parse()

	db, err := store.Open(*dbPath)
	if err != nil {
		log.Fatalf("打开数据库失败: %v", err)
	}
	defer db.Close()

	if *smoke {
		if err := runSmokeTest(db, *dbPath); err != nil {
			log.Fatalf("SMOKE TEST FAILED: %v", err)
		}
		fmt.Println("SMOKE TEST PASSED: 漏洞可达性证明闭环 + 重启恢复验证通过")
		return
	}

	server := httpapi.NewServer(db)
	httpSrv := &http.Server{
		Addr:              *addr,
		Handler:           server.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		log.Printf("task270-sbomreach 服务启动: %s (db=%s)", *addr, *dbPath)
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("HTTP 服务异常退出: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("收到退出信号，正在关闭…")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(ctx)
	log.Println("已优雅退出")
}

// runSmokeTest 执行端到端冒烟测试：
//  1. 创建发布物并导入 SBOM / 调用摘要 / 漏洞条件 / 部署配置；
//  2. 运行可达性分析并断言三种判定（reachable / blocked / insufficient_evidence）；
//  3. 登记例外、创建并发布证明快照、封存发布物；
//  4. 关闭并重新打开同一数据库，验证持久化与重启恢复；
//  5. 全部断言通过后以 0 退出。
func runSmokeTest(db *sql.DB, dbPath string) error {
	relService := service.NewReleaseService(store.NewReleaseStore(db), store.NewSnapshotStore(db))
	analysis := service.NewAnalysisService(
		store.NewReleaseStore(db),
		store.NewComponentStore(db),
		store.NewCallEdgeStore(db),
		store.NewVulnStore(db),
		store.NewConfigStore(db),
		store.NewPathStore(db),
		store.NewExceptionStore(db),
		store.NewSBOMImportStore(db),
		store.NewSnapshotStore(db),
	)
	snapService := service.NewSnapshotService(
		store.NewReleaseStore(db), store.NewPathStore(db),
		store.NewSnapshotStore(db), store.NewExceptionStore(db),
	)

	// 1. 创建发布物
	rel, err := relService.Create("acme-webapp", "1.4.0", "冒烟测试：lib-http 与 lib-ssl 漏洞可达性证明")
	if err != nil {
		return fmt.Errorf("创建发布物: %w", err)
	}
	releaseID := rel.ID
	fmt.Printf("[1] 发布物已创建: %s (%s v%s)\n", releaseID, rel.Name, rel.Version)

	// 2. 导入 SBOM
	sbomDoc := `{
		"components": [
			{"purl":"pkg:golang/acme/web-app@1.4.0","name":"web-app","version":"1.4.0","type":"application"},
			{"purl":"pkg:golang/acme/lib-http@v2.1.0","name":"lib-http","version":"v2.1.0","type":"library","depends_on":["pkg:golang/acme/lib-ssl@v3.0.0"]},
			{"purl":"pkg:golang/acme/lib-ssl@v3.0.0","name":"lib-ssl","version":"v3.0.0","type":"library"}
		]
	}`
	res, err := analysis.ImportSBOM(releaseID, "minimal", "smoke-sbom.json", []byte(sbomDoc))
	if err != nil {
		return fmt.Errorf("导入 SBOM: %w", err)
	}
	fmt.Printf("[2] SBOM 导入完成: 新增 %d / 更新 %d / 共 %d 构件\n",
		res.Imported, res.Updated, res.Total)

	// 3. 导入调用摘要
	edges, err := analysis.AddCallEdges(releaseID, []struct {
		Source string `json:"source"`
		Target string `json:"target"`
		Cond   string `json:"condition_ref,omitempty"`
	}{
		{Source: "main", Target: "parseRequest"},
		{Source: "parseRequest", Target: "lib-http:HTTPRead"},
		{Source: "lib-http:HTTPRead", Target: "lib-ssl:SSLHandshake"},
		{Source: "lib-ssl:SSLHandshake", Target: "lib-ssl:WeakCipherInit", Cond: "feature.legacy_ciphers.enabled"},
		{Source: "main", Target: "healthz"},
	})
	if err != nil {
		return fmt.Errorf("导入调用摘要: %w", err)
	}
	fmt.Printf("[3] 调用摘要导入: %d 条调用边\n", edges)

	// 4. 登记漏洞条件
	must := func(err error, what string) {
		if err != nil {
			fmt.Printf("SMOKE 登记失败 %s: %v\n", what, err)
			os.Exit(1)
		}
	}
	must(analysis.RegisterVuln(releaseID, model.NewVulnCondition(releaseID, "CVE-2024-0001",
		"pkg:golang/acme/lib-http@v2.1.0", "lib-http:HTTPRead", "", "HTTP 请求解析缓冲区溢出", model.SeverityHigh)),
		"CVE-2024-0001")
	must(analysis.RegisterVuln(releaseID, model.NewVulnCondition(releaseID, "CVE-2024-0002",
		"pkg:golang/acme/lib-ssl@v3.0.0", "lib-ssl:WeakCipherInit", "feature.legacy_ciphers.enabled == true",
		"弱密码套件初始化", model.SeverityCritical)),
		"CVE-2024-0002")
	must(analysis.RegisterVuln(releaseID, model.NewVulnCondition(releaseID, "CVE-2024-0003",
		"pkg:golang/acme/lib-ssl@v3.0.0", "main:hiddenImport", "", "隐藏导入路径漏洞", model.SeverityMedium)),
		"CVE-2024-0003")
	fmt.Println("[4] 漏洞条件登记: CVE-2024-0001 / CVE-2024-0002 / CVE-2024-0003")

	// 5. 保存部署配置（legacy ciphers 关闭 → CVE-2024-0002 应被阻断）
	cfg := model.NewDeployConfig(releaseID)
	cfg.EntrySymbols = []string{"main"}
	must(cfg.Set("entry.main.enabled", true), "entry.main.enabled")
	must(cfg.Set("feature.legacy_ciphers.enabled", false), "feature.legacy_ciphers.enabled")
	must(cfg.Set("env.mode", "prod"), "env.mode")
	must(analysis.SaveConfig(cfg), "SaveConfig")
	fmt.Println("[5] 部署配置已保存: entry.main.enabled=true, feature.legacy_ciphers.enabled=false")

	// 6. 运行可达性分析
	result, err := analysis.Analyze(context.Background(), releaseID)
	if err != nil {
		return fmt.Errorf("运行分析: %w", err)
	}
	fmt.Printf("[6] 分析完成: 路径 %d (可达 %d / 阻断 %d / 证据不足 %d), 环 %d\n",
		result.PathCount, result.Reachable, result.Blocked, result.Insufficient, result.CyclesFound)

	// 6a. 断言分析结果
	paths, err := analysis.ListPaths(releaseID)
	if err != nil {
		return err
	}
	byCVE := map[string]string{}
	for _, p := range paths {
		byCVE[p.CVEID] = string(p.Status)
	}
	if got := byCVE["CVE-2024-0001"]; got != "reachable" {
		return fmt.Errorf("断言失败: CVE-2024-0001 期望 reachable，实际 %s", got)
	}
	if got := byCVE["CVE-2024-0002"]; got != "blocked" {
		return fmt.Errorf("断言失败: CVE-2024-0002 期望 blocked，实际 %s", got)
	}
	if got := byCVE["CVE-2024-0003"]; got != "insufficient_evidence" {
		return fmt.Errorf("断言失败: CVE-2024-0003 期望 insufficient_evidence，实际 %s", got)
	}
	fmt.Println("[6a] 判定断言通过: 0001=reachable, 0002=blocked, 0003=insufficient_evidence")

	// 7. 裁决路径 + 登记例外
	var blockedPath *model.ReachPath
	for _, p := range paths {
		if p.CVEID == "CVE-2024-0002" {
			blockedPath = p
		}
	}
	if blockedPath != nil {
		if _, err := analysis.Adjudicate(blockedPath.ID, "smoke-engineer"); err != nil {
			return fmt.Errorf("裁决路径: %w", err)
		}
		if _, err := analysis.RegisterException(releaseID, blockedPath.ID, "CVE-2024-0002",
			"feature.legacy_ciphers.enabled=false，弱密码套件不可达", "smoke-engineer"); err != nil {
			return fmt.Errorf("登记例外: %w", err)
		}
	}
	fmt.Println("[7] 例外已登记: CVE-2024-0002（配置阻断，风险接受）")

	// 8. 创建并发布证明快照
	snap, err := snapService.CreateDraft(releaseID, "cvefeed-2026.08")
	if err != nil {
		return fmt.Errorf("创建快照: %w", err)
	}
	published, err := snapService.Publish(snap.ID)
	if err != nil {
		return fmt.Errorf("发布快照: %w", err)
	}
	fmt.Printf("[8] 快照已发布: v%d, 漏洞 %d (可达 %d / 阻断 %d / 证据不足 %d / 豁免 %d)\n",
		published.Version, published.Summary.TotalVulns,
		published.Summary.ReachableVulns, published.Summary.BlockedVulns,
		published.Summary.InsufficientVulns, published.Summary.ExemptedVulns)

	// 9. 封存发布物
	sealed, err := relService.Seal(releaseID)
	if err != nil {
		return fmt.Errorf("封存发布物: %w", err)
	}
	fmt.Printf("[9] 发布物已封存: status=%s\n", sealed.Status)

	// 10. 关闭并重新打开同一数据库，验证持久化与重启恢复
	if err := db.Close(); err != nil {
		return fmt.Errorf("关闭数据库: %w", err)
	}
	db2, err := store.Open(dbPath)
	if err != nil {
		return fmt.Errorf("重开数据库失败（重启恢复）: %w", err)
	}
	defer db2.Close()

	rel2, err := store.NewReleaseStore(db2).Get(releaseID)
	if err != nil {
		return fmt.Errorf("重启后读取发布物失败: %w", err)
	}
	if rel2.Status != model.ReleaseSealed {
		return fmt.Errorf("重启断言失败: 发布物状态期望 sealed，实际 %s", rel2.Status)
	}
	paths2, err := store.NewPathStore(db2).ListByRelease(releaseID)
	if err != nil || len(paths2) != len(paths) {
		return fmt.Errorf("重启断言失败: 路径数期望 %d，实际 %d (err=%v)", len(paths), len(paths2), err)
	}
	snaps2, err := store.NewSnapshotStore(db2).ListByRelease(releaseID)
	if err != nil || len(snaps2) != 1 {
		return fmt.Errorf("重启断言失败: 快照数期望 1，实际 %d (err=%v)", len(snaps2), err)
	}
	if snaps2[0].Status != model.SnapshotPublished {
		return fmt.Errorf("重启断言失败: 快照状态期望 published，实际 %s", snaps2[0].Status)
	}
	comps2, err := store.NewComponentStore(db2).ListByRelease(releaseID)
	if err != nil || len(comps2) != 3 {
		return fmt.Errorf("重启断言失败: 构件数期望 3，实际 %d (err=%v)", len(comps2), err)
	}
	fmt.Printf("[10] 重启恢复验证通过: 发布物(sealed)/路径(%d)/快照(published v%d)/构件(%d) 全部恢复\n",
		len(paths2), snaps2[0].Version, len(comps2))

	return nil
}
