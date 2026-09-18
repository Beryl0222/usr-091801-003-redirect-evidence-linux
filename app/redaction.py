"""按角色裁剪敏感字段，三类人员看到的字段严格限于各自职责。

- 复核员 reviewer：看证据摘要与来源定位（判定所需），账号标识脱敏；
- 主管 supervisor：看全量字段（冻结、移送决策需要完整定位信息）；
- 审计员 auditor：只看过程与哈希（状态、得分、阈值、审计链），
  摘要、定位、昵称、重组网址一律不可见。
"""

from . import models as m


def mask_id(value):
    if not value:
        return value
    if len(value) <= 2:
        return "***"
    return value[0] + "***" + value[-1]


def redact_fragment(fragment, role):
    f = dict(fragment)
    if role == m.ROLE_AUDITOR:
        f["digest"] = None
        f["locator"] = None
        f["nickname_at_event"] = None
        f["account_id"] = mask_id(f["account_id"])
        f["related_account_id"] = mask_id(f.get("related_account_id"))
        f["redacted"] = True
    elif role == m.ROLE_REVIEWER:
        f["account_id"] = mask_id(f["account_id"])
        f["related_account_id"] = mask_id(f.get("related_account_id"))
    return f


def redact_path(path, role):
    if role in (m.ROLE_REVIEWER, m.ROLE_AUDITOR):
        steps = [dict(s, account_id=mask_id(s["account_id"])) for s in path["steps"]]
    else:
        steps = [dict(s) for s in path["steps"]]
    out = {"steps": steps}
    if role == m.ROLE_AUDITOR:
        out["reassembled_urls"] = []
        out["reassembled_url_count"] = len(path["reassembled_urls"])
    else:
        out["reassembled_urls"] = list(path["reassembled_urls"])
    return out


def redact_suggestion(suggestion, role):
    s = dict(suggestion)
    if role in (m.ROLE_REVIEWER, m.ROLE_AUDITOR):
        s["subject_account_id"] = mask_id(s["subject_account_id"])
        s["implicated_account_ids"] = [mask_id(a) for a in s.get("implicated_account_ids", [])]
    if role == m.ROLE_AUDITOR:
        s["reassembled_url_count"] = len(s.get("reassembled_urls", []))
        s["reassembled_urls"] = []
    return s


def redact_analysis(analysis, role):
    a = {k: v for k, v in analysis.items() if k != "path"}
    a["path"] = redact_path(analysis["path"], role)
    return a


def redact_package(package, role):
    """移送包内含定位信息，仅主管可见全量；其余角色只看元数据。"""
    if role == m.ROLE_SUPERVISOR:
        return dict(package)
    return {
        "package_id": package["package_id"],
        "case_id": package["case_id"],
        "status": package["status"],
        "created_at": package["created_at"],
        "recipient": package["recipient"],
        "receipt_id": package["receipt_id"],
        "dispatched_at": package["dispatched_at"],
        "conclusion_count": len(package["conclusions"]),
        "audit_head": package["audit_head"],
    }
