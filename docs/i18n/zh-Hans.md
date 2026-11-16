# zh-Hans — 简体中文 · 笔记

Catalog: `internal/webui/i18n/catalogs/zh-Hans.json` · golden: `internal/webui/testdata/golden/zh-Hans.txt`

## 1. 读者与语气

国内安全从业者：漏洞运营、应急响应、蓝队、安全研究、补丁管理。日常读的是
CNVD/CNNVD 通告、厂商安全公告、CISA KEV、GitHub 公告。

- 简洁、陈述、偏终端风格；不用"您"，不用感叹号，不用营销语气。
- 这一版是原站中文文案迁移进目录（catalog）后的结果，意思不变；拆分暴露出的个别别扭处做了小修（见第 5 节）。
- 导航保留"路径 + 中文词"（`~/hot 升温`），中文读者需要这个提示。
- 首页叫"正在升温"：指漏洞刚进入更后的阶段，不是热度排行。

## 2. 术语

| 概念 | 用词 | 依据 |
| --- | --- | --- |
| DIS | 披露 | 以 CVE 记录发布时间作为披露时间 |
| PAT | 补丁、补丁记录、修复版本 | GHSA "first patched version" 对应"修复版本" |
| ANA | 技术分析 | 中性；不用"分析文章" |
| POC | 公开 PoC | 业内通行写法，PoC 保留英文 |
| ITW | 在野利用 | 国内通告和厂商公告的通行译法 |
| KEV | CISA KEV、已知被利用漏洞目录 | CISA 目录的通行中文名 |
| due_date | 修复期限、"要求在 X 前修复" | BOD 22-01 的 remediation due date |
| forensic triage | 取证排查 | |
| CNA | 编号分配方 | 比"CNA"直译更好懂；名称原样保留 |
| CVSS 等级 | 严重 / 高危 / 中危 / 低危 / 无 | 国内漏洞通告的通行等级名 |
| SSVC | "CISA 的 SSVC 评估中利用状态为 active" | 取值 active / poc 作为记号保留 |
| bulk import | 批量导入，非实时观测 | |
| backfill | 回填、回填待补 | |
| collectors | 采集器 | 与 CLI 对应 |
| passkey | 通行密钥 | Apple/Google/Microsoft 中文界面的通行译名 |
| sign in / sign out | 登录 / 退出登录 | |
| handle | 用户名（公开显示为 @用户名） | 比"句柄"好懂 |
| display name | 显示名 | |
| sign-in method / provider | 登录方式 / 第三方账号 | 不用"身份提供方"这类协议术语 |
| link / unlink | 关联 / 解除关联 | |
| re-verification | 验证身份 | |
| moderator / admin | 版主 / 管理员 | 顶栏角色徽章 |
| delete account | 删除账号 | 不用"注销"（易与退出登录混淆） |
| tag / tags | 标签 | `tag.*`（2026-11-14） |
| 漏洞类型标签名（XSS、SQL injection、use-after-free、path traversal……） | 保留英文 | 站长规定：技术术语和产品名在所有语言里用原文；中文说明写在 `tag.desc` 里，括注社区常用说法（越权、目录穿越、释放后重用、请求走私……） |
| remote-unauth（AV:N + PR:N + UI:N） | 远程未授权 | 国内通告的通行说法；说明里写清“无需认证，也无需用户交互” |
| no-auth / no-interaction | 无需认证 / 无需用户交互 | 与 CVSS 中文资料的“所需权限：无”“用户交互：无”对应 |
| AV:N / A / L / P | 网络 / 相邻网络 / 本地 / 物理接触 | CVSS 攻击途径的通行译名 |
| ransomware use | 勒索软件利用 | KEV 字段 knownRansomwareCampaignUse 作为记号保留 |
| dimension（type / access / exploit / ecosystem） | 漏洞类型 / 攻击途径 / 利用情况 / 软件包生态 | |
| derived by nday | 由 nday 按固定规则推导 | 必须说清不是 NVD 或编号分配方给出的（NVD 条款） |

- 2026-11-14（`rsch.`、`veil.`、`discussed.`、`nav.discussed`）：X 帖子区叫“研究员讨论”，`/discussed` 叫“研究员热议”，导航用“热议”；“提到”指在 X 上发帖提及。占位下的句子“登录后可阅读 N 条帖子/评论”也是读屏软件读到的内容。

## 3. 诚实用语（固定写法）

| 含义 | 用词 |
| --- | --- |
| 未知 | "时间未知"、"披露时间未知"、"是否被勒索软件使用：未知" |
| 推定 | "由 KEV 推定"、"推定，无直接来源" |
| 不晚于 | `≤ {date}`，"只能给出上限" |
| 未收录 | "未收录"（PoC 库）、"尚未列入 CISA KEV" |
| 尚无记录 | "尚无记录"、"本站还没有补丁记录"（不写"没有补丁"） |

## 4. 排版

- 全角标点（，。：；（）“”）；句末用"。"（测试会检查）。
- 中文与拉丁字母/数字/占位符之间加一个空格（"披露后第 {days} 天进入 KEV"），
  与原站一致；`{stage}已发生` 这类紧贴阶段名的短语保持原站写法不加空格。
- 列表用顿号"、"（`list.and.*`、`list.seq.*` 都是 "{a}、{b}"）；
  句子之间不加空格（`sentence.joiner` 为空）；生命周期条的读屏标签子句用"，"（`strip.sep`）。
- 上游标题用书名号《》（Exploit-DB 条目）；数字分组 `45,965`。

## 5. 改动与疑问

- 改动：GHSA 事件原为一句"…，并附修复提交。"，现在"附修复提交"是独立句
  `ev.ghsa.commits`："公告附有修复提交。"（句子级拆分的代价，意思不变）。
- 改动：Exploit-DB "已由 Exploit-DB 验证"从逗号从句改为独立句。
- 改动：原"披露到进入 KEV"标签（`fact.tplus`）各阶段分别写全；"有补丁记录早于…"
  改为"补丁记录早于 CVE 记录发布 N 天"。
- 改动：rss/api/about 中的 about 改为"关于"；补丁面板小标题 "fix commits"/"advisories"
  改为"修复提交"/"公告"；表头 eco/package/affected/fixed 保留英文（原设计如此）。
- 疑问：`fact.stage` 等事实标签沿用"stage 当前阶段"式（字段名 + 中文），是否保留字段名待定。
- 疑问：`strip.slot` "公开 PoC已发生" 拉丁词与汉字间没有空格，读屏无影响，视觉上不出现。
