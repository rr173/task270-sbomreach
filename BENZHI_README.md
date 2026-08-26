# BENZHI 评测说明

基于 Go 实现的软件物料清单漏洞可达性证明后端服务，一款后端服务，完成 SBOM 与调用摘要导入、条件化调用图上从部署入口到漏洞受影响符号的可达路径搜索、不可达例外裁决与不可变证明快照发布。

## 启动

```bash
CGO_ENABLED=0 GOTOOLCHAIN=local go run ./cmd/task270-sbomreach --addr :8080 --db task270-sbomreach.db
```

## 自检（不启动长驻服务）

```bash
go run ./cmd/task270-sbomreach --smoke-test
```

`--smoke-test` 会真实创建发布物、导入 SBOM/调用摘要/漏洞条件/部署配置、运行可达性分析、裁决例外、发布证明快照并封存，关闭并重新打开同一数据库验证持久化与重启恢复，最后以 0 退出码结束。

## 构建门禁

```bash
CGO_ENABLED=0 GOTOOLCHAIN=local go build ./...
CGO_ENABLED=0 GOTOOLCHAIN=local go vet   ./...
CGO_ENABLED=0 GOTOOLCHAIN=local go test  ./...
go run ./cmd/task270-sbomreach --smoke-test
```

## HTTP API（前缀 /api）

发布物：`POST /api/releases`、`GET /api/releases`、`GET /api/releases/{id}`、`POST /api/releases/{id}/advance`、`POST /api/releases/{id}/seal`
SBOM/构件：`POST /api/releases/{id}/sbom`、`GET /api/releases/{id}/components`
调用摘要：`POST /api/releases/{id}/calls`、`GET /api/releases/{id}/calls`
漏洞条件：`POST /api/releases/{id}/vulns`、`GET /api/releases/{id}/vulns`
部署配置：`POST /api/releases/{id}/configs`、`GET /api/releases/{id}/configs`
分析：`POST /api/analysis/{rid}/run`、`GET /api/analysis/{rid}/paths`、`GET /api/analysis/{rid}/summary`
裁决/例外：`POST /api/paths/{id}/adjudicate`、`POST /api/releases/{id}/exceptions`、`GET /api/releases/{id}/exceptions`
快照：`POST /api/releases/{id}/snapshots`、`GET /api/releases/{id}/snapshots`、`POST /api/snapshots/{id}/publish`、`GET /api/snapshots/{id}`
统计/健康：`GET /api/stats/overview`、`GET /api/releases/{id}/stats`、`GET /api/health`、`GET /api/selfcheck`

## 持久化

SQLite（modernc.org/sqlite，CGO 无关）。建表：releases、components、call_edges、vuln_conditions、deploy_configs、entry_symbols、reach_paths、exceptions、proof_snapshots、sbom_imports、meta。构件按 `(release_id, purl)` 幂等；调用边按 `(release_id, source, target, condition_ref)` 唯一；漏洞条件按 `(release_id, cve_id, affected_symbol)` 唯一；快照按 `(release_id, version)` 唯一。封存快照冻结漏洞库版本与路径证据。
