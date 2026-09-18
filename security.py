"""角色鉴权与字段级脱敏。

三类身份：
- reviewer 复核员：办案所需的完整证据视图（定位、摘要、账号身份）；
- auditor 审计员：只看流程与决定（谁、按哪版规则、阈值、双人确认、审计链），
  不看私密内容片段与来源定位；
- external 外部接收人：只看分配给自己的移送包，且仅保留办案最小必要字段，
  不含内部办案信息（其他案件、审核员身份、申诉讨论）。
"""

import hashlib

ROLE_REVIEWER = "reviewer"
ROLE_AUDITOR = "auditor"
ROLE_EXTERNAL = "external"

# 演示用令牌表；生产应接入统一身份网关
TOKENS = {
    "rev-alice": (ROLE_REVIEWER, "alice"),
    "rev-bob": (ROLE_REVIEWER, "bob"),
    "rev-cao": (ROLE_REVIEWER, "cao"),
    "aud-carol": (ROLE_AUDITOR, "carol"),
    "ext-police": (ROLE_EXTERNAL, "市公安局网安支队"),
}


def authenticate(headers):
    """从 Authorization: Bearer 解析身份。返回 (role, username) 或 None。"""
    raw = headers.get("Authorization", "")
    if not raw.startswith("Bearer "):
        return None
    return TOKENS.get(raw[len("Bearer "):])


def require(role, allowed):
    return role in allowed


def mask_account_id(account_id):
    if not account_id:
        return account_id
    digest = hashlib.sha256(account_id.encode()).hexdigest()[:10]
    return f"ACC-{digest}"


# ---------- 案件视图脱敏 ----------
def redact_case_view(view, role):
    if role == ROLE_REVIEWER:
        return view
    if role == ROLE_AUDITOR:
        return _auditor_case_view(view)
    # 外部接收人不得浏览完整案件视图
    return None


def _strip_event_content(event):
    return {
        "event_id": event["event_id"],
        "source_system": event["source_system"],
        "event_type": event["event_type"],
        "occurred_at": event["occurred_at"],
        # source_ref（私密素材定位）、payload、摘录一律屏蔽
    }


def _auditor_case_view(view):
    case = dict(view["case"])
    return {
        "case": case,
        "retention": view["retention"],
        "events": [_strip_event_content(e) for e in view["events"]],
        "timeline": None,  # 含内容摘录，屏蔽
        "assemblies": [
            {
                "key": a["key"],
                "risk": a["risk"],
                "valid_url": a["valid_url"],
                "source_count": len(a["sources"]),
                "sources": a["sources"],
                # 重组出的网址文本属于内容，审计只关心是否命中与来源数量
            }
            for a in (view["assemblies"] or [])
        ],
        "latest_analysis_id": view["latest_analysis_id"],
        "links": [
            {
                "link_id": l["link_id"],
                "account_id": mask_account_id(l["account_id"]),
                "kind": l["kind"],
                "score": l["score"],
                "status": l["status"],
                "rule_version": l["rule_version"],
                "created_at": l["created_at"],
                "confirmations": l["confirmations"],
                "evidence": {
                    "score": l["evidence"]["score"],
                    "fragments": [
                        {
                            "event_id": f["event_id"],
                            "event_type": f["event_type"],
                            "signal": f["signal"],
                            "weight": f["weight"],
                            # 摘录与 source_ref 屏蔽
                        }
                        for f in l["evidence"].get("fragments", [])
                    ],
                },
            }
            for l in view["links"]
        ],
        "freezes": view["freezes"],
        "transfers": view["transfers"],
    }


# ---------- 移送包对外部接收人的脱敏 ----------
def redact_package(package_row, role, recipient_name=None):
    manifest = dict(package_row["manifest_json"]
                    if isinstance(package_row["manifest_json"], dict)
                    else __import__("json").loads(package_row["manifest_json"]))
    if role == ROLE_REVIEWER:
        return {"package_id": package_row["package_id"], "manifest": manifest}
    if role != ROLE_EXTERNAL:
        return None
    if recipient_name and manifest["recipient"] != recipient_name:
        return None  # 只能查分配给本单位的包

    return {
        "package_id": package_row["package_id"],
        "manifest": {
            "package_type": manifest["package_type"],
            "case_id": manifest["case_id"],
            "recipient": manifest["recipient"],
            "created_at": manifest["created_at"],
            "manifest_sha256": manifest.get("manifest_sha256"),
            "rule_version": manifest["rule_version"],
            "subject_account": mask_account_id(manifest["account_id"]),
            "conclusion_score": manifest["evidence"]["score"],
            "assembled_urls": [
                {"text": a["text"], "domain": a["domain"], "risk": a["risk"]}
                for a in manifest["evidence"].get("assemblies", [])
            ],
            "evidence_index": [
                {
                    "source_system": e["source_system"],
                    "source_ref": e["source_ref"],      # 凭定位正式调证
                    "event_type": e["event_type"],
                    "occurred_at": e["occurred_at"],
                    "content_sha256": e["content_sha256"],
                    "excerpt": e["excerpt"],
                    # 共享案件列表、内部事件 ID 等办案信息不导出
                }
                for e in manifest["events"]
            ],
            "review_summary": {
                "two_person_confirmed": len(manifest["confirmations"]) >= 2,
                "reviewer_count": len({c["reviewer"] for c in manifest["confirmations"]}),
                # 审核员身份不对外，仅给双人结论与时间
                "confirmed_at": sorted(c["confirmed_at"] for c in manifest["confirmations"]),
            },
            "retention_until": manifest.get("retention_until"),
        },
    }
