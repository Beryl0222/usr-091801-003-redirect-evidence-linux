"""版本化关系规则引擎。

纯函数、无副作用：输入事件列表与昵称解析器，输出每个账号的评分、
判定与证据。规则版本与参数随分析结果一起快照，旧版本可随时原样复跑。

升级原则：新增版本只影响升级之后发起的分析；历史关联记录其产生时的
版本与阈值，引擎保证同版本同输入结果一致。
"""

import re
import unicodedata
from copy import deepcopy

# ---- v1：上线版本 -------------------------------------------------------
RULES_V1 = {
    "version": "v1",
    "threshold": 55,
    "weights": {
        "piece": 8,            # 每一个参与重组的片段
        "assembly": 20,        # 跨片段成功拼出完整网址
        "risk_domain": 20,     # 命中风险域名库
        "qr": 25,              # 直播画面短时二维码
        "audio": 20,           # 音频口播解码出同一网址
        "merchant": -40,       # 已备案商户减分
        "report_context": 0,   # v1 未识别“举报语境”
    },
    "risk_domains": ["dianzan88.com", "huanpi163.net", "taozuan-vx.com"],
    "codewords": {
        "三打不溜": "www",
        "三达不溜": "www",
        "点康姆": ".com",
        "康姆": "com",
        "点": ".",
        "丶": ".",
    },
    "report_markers": [],
    "min_sources": 2,
}

# ---- v2：规则升级（新暗语、跨源加权、举报语境排除，阈值下调） -----------
RULES_V2 = {
    "version": "v2",
    "threshold": 50,
    "weights": {
        "piece": 10,
        "assembly": 20,
        "risk_domain": 20,
        "qr": 25,
        "audio": 22,
        "merchant": -50,
        "report_context": -30,
        "cross_source": 6,     # 每个超出最低来源数的额外来源
    },
    "risk_domains": ["dianzan88.com", "huanpi163.net", "taozuan-vx.com"],
    "codewords": {
        "三打不溜": "www",
        "三达不溜": "www",
        "点卡姆": ".com",       # 新增暗语
        "点康姆": ".com",
        "康姆": "com",
        "卡姆": "com",
        "点": ".",
        "丶": ".",
        "加薇": "+vx",
        "薇信": "vx",
        "卫星": "vx",
        "企鹅": "qq",
        "蔻蔻": "qq",
    },
    "report_markers": ["举报", "骗子", "谨防", "别信", "反诈", "防骗"],
    "min_sources": 2,
}

RULE_VERSIONS = {"v1": RULES_V1, "v2": RULES_V2}

_LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "@": "a", "$": "s"})
_SEPARATORS = re.compile(r"[\s_·•・|｜​‌‍＿]+")
_URL_RE = re.compile(r"^(?:https?://)?(?:www\.)?[a-z0-9-]+(?:\.[a-z0-9-]{2,})+(?:/[^\s]*)?$")
_DOMAIN_RE = re.compile(r"(?:https?://|//)?(?:www\.)?([a-z0-9-]+\.[a-z]{2,})(?:/|$)")


def get_rules(version):
    if version not in RULE_VERSIONS:
        raise ValueError(f"未知规则版本: {version}")
    return deepcopy(RULE_VERSIONS[version])


def normalize(text, rules, leet=True):
    """归一化：全角转半角、口播暗语替换、形近字、去分隔符。

    拼网址时 leet=False：域名本身可合法含数字（如 huanpi163），
    数字形近替换只用于普通文本匹配。
    """
    s = unicodedata.normalize("NFKC", text or "").lower()
    for word in sorted(rules["codewords"], key=len, reverse=True):
        s = s.replace(word, rules["codewords"][word])
    if leet:
        s = s.translate(_LEET)
    s = _SEPARATORS.sub("", s)
    return s


def _excerpt(event, length=60):
    payload = event["payload"]
    text = payload.get("text") or payload.get("summary") or ""
    if payload.get("qr"):
        text = f"{text}（画面闪现二维码约{payload['qr'].get('duration_seconds', '?')}秒）"
    return text[:length]


def _domain_of(assembled):
    match = _DOMAIN_RE.search(assembled)
    return match.group(1) if match else None


def analyze(events, rule_version="v2", name_at=None, params_override=None):
    """对案件事件集合跑一次自动关联分析。

    返回结构含输入指纹、重组结果、逐账号候选与时间线；调用方负责持久化。
    params_override 用于历史复现：严格按当时保存的参数快照计算。
    """
    rules = get_rules(rule_version)
    if params_override is not None:
        rules = {**rules, **params_override}
    name_at = name_at or (lambda _a, _t: None)
    ordered = sorted(events, key=lambda e: e["occurred_at"])

    # 1) 按片段分组重组（片段可来自昵称、直播、音频、评论、收藏夹等不同来源）
    groups = {}
    for event in ordered:
        frag = event["payload"].get("fragment")
        if not frag:
            continue
        groups.setdefault(frag.get("key", "default"), []).append(event)

    assemblies = []
    for key in sorted(groups):
        pieces = sorted(groups[key], key=lambda e: e["payload"]["fragment"]["seq"])
        seqs = [p["payload"]["fragment"]["seq"] for p in pieces]
        complete = seqs == list(range(len(seqs)))
        joined = "".join(
            normalize(p["payload"]["fragment"].get("text", ""), rules, leet=False)
            for p in pieces
        )
        valid_url = bool(_URL_RE.match(joined)) and "." in joined
        domain = _domain_of(joined) if valid_url else None
        risk = bool(domain and any(domain == d or domain.endswith("." + d)
                                   for d in rules["risk_domains"]))
        sources = sorted({p["source_system"] for p in pieces})
        assemblies.append({
            "key": key,
            "text": joined,
            "complete": complete,
            "valid_url": valid_url,
            "domain": domain,
            "risk": risk,
            "sources": sources,
            "event_ids": [p["event_id"] for p in pieces],
            "accounts": sorted({p["account_id"] for p in pieces if p.get("account_id")}),
            "report_context": any(
                marker in (p["payload"].get("text") or "")
                for p in pieces for marker in rules["report_markers"]
            ),
        })

    # 2) 逐账号归因打分
    by_id = {e["event_id"]: e for e in ordered}
    candidates = {}

    def candidate(account_id):
        return candidates.setdefault(account_id, {
            "account_id": account_id, "score": 0, "signals": [],
            "assemblies": [], "timeline_event_ids": [],
        })

    for asm in assemblies:
        account = asm["accounts"][0] if asm["accounts"] else None
        if account is None:
            continue
        cand = candidate(account)
        cand["assemblies"].append(asm["key"])
        w = rules["weights"]

        for event_id in asm["event_ids"]:
            cand["score"] += w["piece"]
            cand["signals"].append({
                "type": "piece", "weight": w["piece"], "event_id": event_id,
                "detail": f"在 {by_id[event_id]['source_system']} 提供导流片段",
            })

        if asm["valid_url"]:
            cand["score"] += w["assembly"]
            cand["signals"].append({
                "type": "assembly", "weight": w["assembly"],
                "detail": f"跨{len(asm['sources'])}个来源拼出 {asm['text']}",
            })
            extra_sources = max(0, len(asm["sources"]) - rules["min_sources"])
            if extra_sources and w.get("cross_source"):
                bonus = w["cross_source"] * extra_sources
                cand["score"] += bonus
                cand["signals"].append({
                    "type": "cross_source", "weight": bonus,
                    "detail": f"来源分散在 {len(asm['sources'])} 个检测系统",
                })
        if asm["risk"]:
            cand["score"] += w["risk_domain"]
            cand["signals"].append({
                "type": "risk_domain", "weight": w["risk_domain"],
                "detail": f"域名 {asm['domain']} 命中风险库",
            })
        if asm["report_context"] and w["report_context"]:
            cand["score"] += w["report_context"]
            cand["signals"].append({
                "type": "report_context", "weight": w["report_context"],
                "detail": "片段语境为举报/反诈提醒，非导流本身",
            })

        # 同账号的音频口播解码出该域名
        if asm["domain"]:
            for event in ordered:
                if event.get("account_id") != account:
                    continue
                if event["event_type"] != "audio_transcript":
                    continue
                spoken = normalize(event["payload"].get("text", ""), rules, leet=False)
                if asm["domain"] in spoken and event["event_id"] not in asm["event_ids"]:
                    cand["score"] += w["audio"]
                    cand["signals"].append({
                        "type": "audio", "weight": w["audio"],
                        "event_id": event["event_id"],
                        "detail": "音频暗语口播同一域名",
                    })

    # 二维码（直播瞬间）
    for event in ordered:
        if event["event_type"] != "image_summary":
            continue
        qr = event["payload"].get("qr")
        account = event.get("account_id")
        if qr and account:
            cand = candidate(account)
            cand["score"] += rules["weights"]["qr"]
            cand["signals"].append({
                "type": "qr", "weight": rules["weights"]["qr"],
                "event_id": event["event_id"],
                "detail": f"直播画面短时二维码 {qr.get('duration_seconds', '?')} 秒",
            })

    # 已备案商户
    for event in ordered:
        if event["payload"].get("verified_merchant") and event.get("account_id"):
            cand = candidate(event["account_id"])
            cand["score"] += rules["weights"]["merchant"]
            cand["signals"].append({
                "type": "merchant", "weight": rules["weights"]["merchant"],
                "event_id": event["event_id"],
                "detail": "账号持有备案商户资质",
            })

    for cand in candidates.values():
        cand["timeline_event_ids"] = [
            e["event_id"] for e in ordered
            if e.get("account_id") == cand["account_id"]
            or e["event_id"] in {s.get("event_id") for s in cand["signals"]}
        ]
        cand["decision"] = "suggest" if cand["score"] >= rules["threshold"] else "below_threshold"

    timeline = [{
        "event_id": e["event_id"],
        "source_system": e["source_system"],
        "source_ref": e["source_ref"],
        "event_type": e["event_type"],
        "account_id": e.get("account_id"),
        "nickname_at_time": name_at(e.get("account_id"), e["occurred_at"]),
        "occurred_at": e["occurred_at"],
        "excerpt": _excerpt(e),
    } for e in ordered]

    return {
        "rule_version": rules["version"],
        "params": {k: v for k, v in rules.items() if k != "version"},
        "input_event_ids": [e["event_id"] for e in ordered],
        "assemblies": assemblies,
        "candidates": sorted(candidates.values(), key=lambda c: -c["score"]),
        "timeline": timeline,
    }


def replay(events, rule_version, params_snapshot):
    """以历史版本与参数快照复跑；返回结果与快照是否一致的比对。"""
    current = get_rules(rule_version)
    result = analyze(events, rule_version, params_override=params_snapshot)
    # 与“当前同版本基线参数”的差异，用于演示“只影响新分析”
    drifted = {
        key: {"snapshot": params_snapshot.get(key), "current": current.get(key)}
        for key in ("threshold", "weights")
        if params_snapshot.get(key) != current.get(key)
    }
    consistent = result["params"] == params_snapshot
    return result, consistent, drifted
