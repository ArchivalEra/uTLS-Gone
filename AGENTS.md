# AGENTS.md — uTLS-Gone 仓库作业规程

本文件是 agent 在本仓干活的常驻规则。项目介绍见 [README.md](README.md) / [README.zh.md](README.zh.md)。

## 推送路径：永久关闭（终态，非临时故障）

**本仓的 GitHub 写路径已永久下线。** 节点侧 gh 凭据是 `PlumHelper`（只读：
pull=true / push=false / admin=false），这是**终态**，不是过渡——ArchivalEra 的
token 不会再次下发，也不要等待凭据恢复。

- **不要** `git push`、不要 fork、不要提 PR、不要试写路径——这些路已确认关闭，重试只会收到 protected branch 拒绝。
- **不要**用 `gh api` 改分支保护或仓库配置；保护状态对只读账号不可见是预期行为。
- **交付路径（唯一合法路径）**：在本地仓库完成修改并验证 → 通过 wo-u 电话网向
  `wo-u-maintainer` 报告变更内容（diff 摘要 / finding 清单 / 证据）→ 由站长侧
  （ArchivalEra 账号）代为落库（合入 main）。
- 本地 git config 不用改（user.name / user.email 保持原值）；变的只是「落库」这一步永远不发生在节点侧。

## 仓库规矩

- **判据文化**：每个行为都要有可复跑的判据；文档数字只引用不手抄。
  `ci.yml` 的六个 job 就是六类判据（rust / patch-repro / ech-offline / upstream /
  reality-stack / upstream-no-skip），改行为先想判据怎么红。
- **quality-assessment.yml**：本地代码质量评估（PR/每周/手动触发），复用 ci.yml 既有
  判据，不新增 lint 规则。shellcheck 以零豁免方式验证两个 POSIX sh 脚本
  （`crates/rustls-fork/verify-patch.sh`、`crates/utls/tests/fixtures/gen-reference/run-upstream-suite.sh`）。
  多检查在同一 runner 顺序执行时注意共享参照树的隔离：`upstream` 必须先于
  `ech-server`（后者会往 `/tmp/utls-ref/utls-master` 复制探针），探针复制后立即清理。
- **README 是门面**：8 枚 badge 与两份 bench SVG 是点名资产，改 README 时不能丢；
  README.md 与 README.zh.md 是同一条断言的两份拷贝，改一份必须同批改另一份。
- **vendored 树纪律**：`crates/rustls` 是带 FORK(utls-rs) 标记的 vendored rustls；
  不要在里面跑 `cargo fmt`（会污染未改动的上游文件，判据①′会红）。改 fork 语义后
  必须重新生成 `patch.diff` 并跑 `sh crates/rustls-fork/verify-patch.sh`。
- **版本对齐**：workspace 四 crate（utls / utls-engine / reality / x25519-os）版本同步改。
- **无未结 issue**：新工作以 issue 或 wo-u 指令为准，不自立题目。
