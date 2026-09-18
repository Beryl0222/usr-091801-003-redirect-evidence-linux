"""关联规则版本、导流路径重建与按快照复现。

规则是版本化的：每次分析把当时生效的阈值整体快照存进分析记录，
之后规则升级只影响新分析；旧决定永远可以按当时阈值复现。
"""

import re
from datetime import datetime

# 默认规则 v1：单一片段不足以判定，需要跨渠道多片段共同构成路径
DEFAULT_RULE_V1 = {
    "version": "v1",
    "channel_weights": {
        "直播瞬间": 2,
        "音频": 2,
        "评论": 1,
        "昵称": 1,
        "收藏夹": 1,
        "正文": 1,
        "关注关系": 1,
    },
    "default_channel_weight": 1,
    "min_distinct_channels": 2,
    "min_score": 4,
    "window_hours": 72,
    "retention_days": 180,
}

# 摘要中拆分网址片段的标记格式：…片段[1/2]: "hxekle"
URL_PART_RE = re.compile(r'片段\[(\d+)/(\d+)\]\s*[:：]\s*"([^"]+)"')
DOMAIN_RE = re.compile(r"^(?:https?://)?[a-z0-9][a-z0-9.-]*\.[a-z]{2,}(?:/\S*)?$")


def _parse_time(value):
    return datetime.fromisoformat(str(value).replace("Z", "+00:00"))


def build_path(fragments):
    """按发生时间排序重建导流路径，并尝试把拆散在各片段里的网址重组出来。"""
    ordered = sorted(fragments, key=lambda f: (f["occurred_at"], f["fragment_id"]))
    steps = [
        {
            "fragment_id": f["fragment_id"],
            "channel": f["channel"],
            "occurred_at": f["occurred_at"],
            "account_id": f["account_id"],
            "content_hash": f["content_hash"],
        }
        for f in ordered
    ]
    parts = {}
    total = None
    for fragment in ordered:
        for index, count, text in URL_PART_RE.findall(fragment["digest"]):
            total = int(count)
            parts[int(index)] = text
    reassembled = []
    if total and len(parts) == total:
        candidate = "".join(parts[i] for i in range(1, total + 1))
        if DOMAIN_RE.match(candidate):
            reassembled.append(candidate)
    return {"steps": steps, "reassembled_urls": reassembled}


def score_path(path, ruleset):
    """按渠道去重计分：同一渠道出现多次只记一次权重。"""
    weights = ruleset["channel_weights"]
    channels = []
    for step in path["steps"]:
        if step["channel"] not in channels:
            channels.append(step["channel"])
    score = sum(weights.get(c, ruleset.get("default_channel_weight", 1)) for c in channels)
    return score, channels


def within_window(path, window_hours):
    if len(path["steps"]) < 2:
        return True
    times = [_parse_time(step["occurred_at"]) for step in path["steps"]]
    return (max(times) - min(times)).total_seconds() <= window_hours * 3600


def evaluate(fragments, ruleset):
    """纯函数：给定片段集合与规则（或历史快照），输出路径、得分与是否达到建议阈值。

    复现时传入分析记录里的 threshold_snapshot，即可按当时阈值得到同样结论。
    """
    path = build_path(fragments)
    score, channels = score_path(path, ruleset)
    passed = (
        len(channels) >= ruleset["min_distinct_channels"]
        and score >= ruleset["min_score"]
        and within_window(path, ruleset["window_hours"])
    )
    return {"path": path, "score": score, "channels": channels, "passed": passed}
