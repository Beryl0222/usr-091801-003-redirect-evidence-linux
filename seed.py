"""把 samples/events.json 载入存储；支持幂等重复载入（事件去重）。"""

import json

from workflow import Workflow


def load(store, path="samples/events.json"):
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)

    for case in data.get("cases", []):
        if not store.get_case(case["case_id"]):
            store.create_case(
                case["case_id"],
                case["title"],
                case.get("retention_until"),
                actor="seed",
            )

    wf = Workflow(store)
    ingested = 0
    deduped = 0
    for event in data.get("events", []):
        event = dict(event)
        case_id = event.pop("case_id", None)
        result = wf.ingest(event, case_id=case_id, actor="seed")
        ingested += 1 if result["created"] else 0
        deduped += 0 if result["created"] else 1

    shared = 0
    for share in data.get("shares", []):
        if wf.share_clue(share["case_id"], share["event_id"], actor="seed"):
            shared += 1

    return {"ingested": ingested, "deduped": deduped, "shared": shared}


if __name__ == "__main__":
    from store import Store

    stats = load(Store(":memory:"))
    print("样例载入:", stats)
