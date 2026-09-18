# 隐蔽导流证据协查

内容安全案件协查后端：汇集各检测系统（直播瞬间、音频转写、正文、评论、昵称、收藏夹）产生的**定位信息、摘要与内容哈希**，跨来源重建有时间顺序的隐蔽导流路径；自动关联只形成建议，双人确认后才冻结证据并生成外部移送包，误关联可申诉撤销但审计永不消失。

原始私密素材始终由来源系统保管，本服务**不复制原始素材**。

## 快速开始

```bash
python3 service.py --check            # 基础自检
python3 service.py --seed samples/events.json --port 8000   # 带样例启动
python3 demo.py                       # 端到端验收演示（断言式）
npm test                              # 全部单元测试 + 演示
```

仅依赖 Python 3 标准库（SQLite），无第三方依赖。

## 领域模型与状态

```
收集中 → 待初审 → 待复核 → 已冻结 → 已移送
                    │          │
                    └──────── 申诉中 → 已纠正（撤销关联，冻结快照与审计保留）
```

- **事件（events）**：来源系统上报的片段，含 `source_system/source_ref` 定位、`occurred_at`、摘要与 SHA-256；按 `(source_system, source_ref)` 幂等去重，重复上报只写一条 `event.dedup` 审计。
- **账号（accounts）**：身份以 `account_id` 为准；改名只追加 `account_names` 时间段，时间线按事件发生时昵称呈现。
- **案件（cases）**：案件与事件多对多（`case_events`），跨案件共享线索是**引用而非复制**；案件带 `retention_until` 保全期限。
- **分析（analyses）**：每次跑规则都保存规则版本、完整参数（阈值/权重/词库）、输入事件 ID 与结果快照。
- **关联（links）**：自动分析只产生 `suggested`；无任何直接处罚动作。
- **确认（confirmations）**：必须两名**不同**复核员，第二人确认瞬间生成只读冻结快照（`frozen_evidence`）。
- **移送包（transfer_packages）**：冻结后才能生成，清单含 SHA-256，外部凭来源定位正式调证。
- **申诉（appeals）**：`reversed` 撤销关联、案件进入已纠正；冻结记录与移送包不删除。
- **审计（audit_log）**：所有状态变更落审计；`events / audit_log / frozen_evidence / transfer_packages` 为只追加表，SQLite 触发器拒绝任何 UPDATE/DELETE。

## 版本化规则引擎

| | v1（旧） | v2（现） |
|---|---|---|
| 建议阈值 | 55 | 50 |
| 举报/反诈语境 | 不识别（权重 0） | −30 分排除 |
| 音频口播 | 20 | 22 |
| 备案商户 | −40 | −50 |
| 新暗语（点卡姆/加薇/企鹅…） | 无 | 有 |
| 跨来源加成 | 无 | 每多一个来源 +6 |

规则能力：全角半角归一、口播暗语替换、形近字、去分隔符；按 `fragment.key + seq` 把拆散在不同系统的片段重组成网址，再校验域名合法性与风险域名库，叠加短时二维码、音频口播同音域名、备案商户减分。

**升级只影响新分析**：历史关联永久记录其产生时的 `rule_version` 与参数快照，`GET /v1/analyses/{id}/replay` 用该快照原样复算（演示中 v1 旧决定 56 分 suggest，在现行 v2 下复现仍为 56 分，而同一案件用 v2 新分析只有 30 分、不再建议）。

## API（Bearer 令牌）

| 角色 | 令牌 | 权限 |
|---|---|---|
| 复核员 | `rev-alice` / `rev-bob` / `rev-cao` | 建案、接入、分析、确认、冻结、移送、申诉、完整证据视图 |
| 审计员 | `aud-carol` | 只读案件流程视图 + `/v1/audit` 全审计链；看不到内容摘录、source_ref、重组网址文本，账号哈希化 |
| 外部接收人 | `ext-police`（市公安局网安支队） | 只能读分配给本单位的移送包；账号哈希化、无审核员身份、无内部办案信息 |

```
POST /v1/cases                       建案（可带 retention_until）
POST /v1/events                      接入事件（body 可带 case_id，幂等）
POST /v1/cases/{id}/analyze          跑自动关联（?rule_version=v2，默认现行版）
GET  /v1/cases/{id}                  案件视图：时间线/重组/建议/证据回溯
POST /v1/cases/{id}/links/{lid}/confirm   复核员确认（两人不同才冻结）
POST /v1/cases/{id}/links/{lid}/appeal    发起误关联申诉
POST /v1/appeals/{aid}/resolve       upheld | reversed
POST /v1/cases/{id}/transfer         冻结后生成移送包
GET  /v1/packages/{pid}              移送包（按角色/归属脱敏）
GET  /v1/analyses/{aid}/replay       旧决定按当时参数复现
POST /v1/cases/{id}/share            跨案件共享线索（引用，不复制）
GET  /v1/accounts/{aid}              改名历史
GET  /v1/audit                       审计日志（仅审计员）
```

## 验收演示（python3 demo.py）

1. 重复上报去重、账号改名时间线、跨案共享、保全期限届满标记；
2. 拆在昵称/直播 OCR/音频/评论/收藏夹的片段跨 4 个来源拼回 `www.dianzan88.com/x6`，按时间排序；
3. 同一复核员重复确认无效，两名不同复核员后才冻结，证据逐条可回到片段与来源；
4. 外部移送包：哈希账号、双人结论、来源定位+内容哈希，无内部信息；
5. **误关联申诉**：反诈举报人在 v1 下 56 分被误判 → 冻结 → v2 新分析 30 分不建议 → 申诉撤销、案件已纠正、冻结与审计保留；
6. **旧阈值复现**：旧分析按 v1/阈值55 复算仍是 56 分 suggest；
7. 三角色字段隔离逐条断言；只追加表的 DELETE/UPDATE 被触发器拒绝。

## 文件结构

```
store.py     SQLite 只追加存储与审计触发器
rules.py     v1/v2 纯函数规则引擎（重组、打分、复现）
workflow.py  案件工作流（接入/分析/双人确认/冻结/移送/申诉/复现）
security.py  角色鉴权与字段级脱敏
api.py       HTTP 路由与角色门禁
service.py   服务入口（/health 与 /v1/*）
seed.py      样例加载（幂等）
samples/     事件样例（含重复上报、改名、共享、届满保全）
demo.py      端到端验收演示
test_*.py    契约/规则/工作流/API 测试
```
