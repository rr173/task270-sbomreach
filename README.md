# task270-sbomreach 软件物料清单漏洞可达性证明服务

## 业务定位

产品安全工程师需要证明：SBOM（软件物料清单）中某个已知漏洞依赖，在当前部署入口与配置条件下究竟**可达**还是被**阻断**。本服务导入 SBOM、调用摘要、漏洞条件与部署配置，构造条件化调用图，搜索从启用入口到易受影响符号的路径，输出可追溯的漏洞可达性证明。

## 快速开始

```bash
# 端到端冒烟测试（真实建库、分析、快照、封存、重启恢复）
CGO_ENABLED=0 GOTOOLCHAIN=local go run ./cmd/task270-sbomreach --smoke-test

# 启动服务
CGO_ENABLED=0 GOTOOLCHAIN=local go run ./cmd/task270-sbomreach --addr :8080 --db task270-sbomreach.db
```

## 核心闭环

1. 创建发布物（release）
2. 导入 SBOM（构件 + 依赖）→ 导入调用摘要（符号调用边）→ 登记漏洞条件（CVE + 受影响符号 + 前置条件）→ 保存部署配置（入口 + 条件键值）
3. 运行可达性分析：条件化调用图 DFS，输出 `reachable / blocked / insufficient_evidence` 三类判定路径
4. 工程师裁决路径、登记不可达例外
5. 创建并发布不可变证明快照（冻结漏洞库版本与路径证据）
6. 封存发布物

## 状态机

- 发布物：`receiving → composing → pending_review → publishable → sealed`
- 构件：`raw → resolved → vulnerable / exempted`
- 路径：`candidate → reachable / blocked / insufficient_evidence → confirmed`
- 快照：`draft → published → superseded`

## API 一览（前缀 /api）

| 能力 | 入口 |
| --- | --- |
| 创建/列表/详情发布物 | `POST/GET /api/releases`、`GET /api/releases/{id}` |
| 推进状态机 / 封存 | `POST /api/releases/{id}/advance`、`POST /api/releases/{id}/seal` |
| 导入 SBOM / 列构件 | `POST/GET /api/releases/{id}/sbom`、`GET /api/releases/{id}/components` |
| 导入/列调用摘要 | `POST/GET /api/releases/{id}/calls` |
| 登记/列漏洞条件 | `POST/GET /api/releases/{id}/vulns` |
| 保存/读部署配置 | `POST/GET /api/releases/{id}/configs` |
| 运行分析 / 路径 / 汇总 | `POST /api/analysis/{rid}/run`、`GET /api/analysis/{rid}/paths`、`GET /api/analysis/{rid}/summary` |
| 裁决路径 / 例外 | `POST /api/paths/{id}/adjudicate`、`POST/GET /api/releases/{id}/exceptions` |
| 快照 | `POST/GET /api/releases/{id}/snapshots`、`POST /api/snapshots/{id}/publish`、`GET /api/snapshots/{id}` |
| 统计 / 健康 / 自检 | `GET /api/stats/overview`、`GET /api/releases/{id}/stats`、`GET /api/health`、`GET /api/selfcheck` |

## 部署配置条件键约定

- `entry.<symbol>.enabled`（bool）：入口符号是否启用
- `feature.<name>`（bool）：特性开关（调用边条件引用）
- `env.mode`（string）：运行环境
- `limit.<name>`（float64）：数值上限

漏洞前置条件表达式语法：`<key> == <value>` / `!=` / `in v1,v2` / `> n` / `>= n`。

## 持久化与重启恢复

全部数据落 SQLite（`modernc.org/sqlite` 纯 Go 驱动，CGO 无关）。`--smoke-test` 关闭并重开同一数据库，验证发布物、构件、路径与快照全部恢复。

## 目录结构

```
cmd/task270-sbomreach/    入口（--addr / --db / --smoke-test）
internal/
├── model/                实体与领域错误
├── store/                SQLite 持久化（11 个仓库）
├── sbom/                 SBOM 解析与批量导入
├── callgraph/            条件化调用图构建与环检测
├── vuln/                 漏洞条件匹配与前置条件求值
├── reach/                可达性分析核心（条件化 DFS）
├── snapshot/             证明快照与封存冻结
├── service/              编排层
└── httpapi/              HTTP API 层
```
