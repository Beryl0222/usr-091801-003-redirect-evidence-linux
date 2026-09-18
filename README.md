# 隐蔽导流证据协查

内容安全团队的案件协查后端：汇集各检测系统上报的隐蔽导流线索（直播画面摘要、音频转写、正文、评论、昵称、收藏夹与账号关系），重建有时间顺序的导流路径，支撑人工复核、证据冻结与外部移送。

## 边界与硬约束

- **不复制原始私密素材**：入库只接收定位信息（locator）、摘要（digest）与内容哈希；携带 `raw_content` 等原始素材字段的载荷直接拒绝（400）。原始素材由来源系统保管，移送包只装结论、定位与哈希，供外部机构调证。
- **自动关联只形成建议**：分析产出关联建议与时间序路径，系统没有任何自动处罚路径；冻结与移送必须两名不同人员依次确认。
- **误关联可撤销，审计不能消失**：申诉成立只把建议置为 `已撤销`，记录保留；审计为只增不减的哈希链，`GET /audit/verify` 可校验完整性。
- **规则升级只影响新分析**：每次分析整体快照当时阈值；`POST /analyses/{id}/reproduce` 按快照复跑，证明旧决定在当时规则下仍然成立。

## 案件状态机

`收集中 → 待初审 → 待复核 → 已冻结 → 已移送`，申诉支线：`待初审/待复核 → 申诉中 → 已纠正`（驳回则回到原状态）。冻结/移送后的更正须走专案流程。

## 角色与字段可见性

| 字段 | 复核员 reviewer | 主管 supervisor | 审计员 auditor |
|---|---|---|---|
| 摘要 digest / 定位 locator | ✓ | ✓ | ✗（仅见哈希） |
| 账号标识 / 关联账号 | 脱敏 | ✓ | 脱敏 |
| 重组网址 | ✓ | ✓ | ✗（仅见计数） |
| 移送包内容 | 仅元数据 | ✓ | 仅元数据 |
| 得分/阈值/状态/审计链 | ✓ | ✓ | ✓ |

检测系统账号（`system`）只能入库事件，不可见任何案件结论。申诉处理人不得是申诉人本人或原确认人（回避）。

## 事件样例覆盖

同一内容重复上报（按来源事件号幂等、按内容哈希合并计数）、账号改名（按 account_id 归并、昵称留痕、片段记录当时昵称）、跨案件共享线索（`POST /cases/{id}/shared-clues`，参与目标案件分析）、证据保全期限（冻结时按规则快照设定 `retention_until`，期限内清除被拒绝）。

## 主要接口

```
POST /cases                         创建案件
POST /events                        线索入库（幂等）
POST /cases/{id}/analyze            自动关联分析（当前规则版本）
POST /analyses/{id}/reproduce       按当时阈值快照复现旧决定
GET  /suggestions/{id}              结论对应的证据片段与来源
POST /suggestions/{id}/confirm      双人确认（同一人重复确认被拒）
POST /suggestions/{id}/appeals      申诉
POST /appeals/{id}/resolve          申诉处理（回避校验）
POST /cases/{id}/freeze             冻结证据（含保全期限）
POST /cases/{id}/transfer-packages  生成移送包
POST /transfer-packages/{id}/dispatch  外部移送
POST /cases/{id}/shared-clues       跨案件共享线索
GET  /cases/{id}                    案件视图（按角色脱敏）
GET  /cases/{id}/audit              案件审计链
GET  /cases/{id}/retention          保全期限报告
GET  /audit/verify                  审计链整体校验
GET  /rules · POST /rules           规则版本查询/升级（仅主管）
POST /maintenance/purge             过期清除（保全期内拒绝）
```

除 `/health` 外均需请求头 `X-Actor-Id` 与 `X-Actor-Role`（`system|reviewer|supervisor|auditor`）。

## 运行

```bash
python3 service.py --check        # 基础检查
python3 service.py --port 8000    # 启动服务
npm test                          # 全部测试（契约 + 领域 + 接口）
python3 demo.py                   # 交付演示：误关联申诉、外部移送、旧决定复现、三角色字段隔离
```
