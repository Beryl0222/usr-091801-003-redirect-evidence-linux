"""领域常量：案件状态机、建议/申诉状态、角色与事件类型。"""

# 案件状态机：收集中 → 待初审 → 待复核 → 已冻结 → 已移送
# 申诉支线：待初审/待复核 → 申诉中 → 已纠正（或驳回后回到原状态）
CASE_COLLECTING = "收集中"
CASE_PENDING_INITIAL = "待初审"
CASE_PENDING_REVIEW = "待复核"
CASE_FROZEN = "已冻结"
CASE_TRANSFERRED = "已移送"
CASE_APPEALING = "申诉中"
CASE_CORRECTED = "已纠正"

# 自动关联建议状态：自动关联只形成建议，绝不直接处罚
SUGGESTION_PENDING = "待确认"
SUGGESTION_CONFIRMED = "已确认"
SUGGESTION_REVOKED = "已撤销"

# 申诉状态
APPEAL_PENDING = "待处理"
APPEAL_UPHELD = "已成立"
APPEAL_REJECTED = "已驳回"

# 角色：system 为检测系统接入账号，三类人员为复核员/主管/审计员
ROLE_SYSTEM = "system"
ROLE_REVIEWER = "reviewer"
ROLE_SUPERVISOR = "supervisor"
ROLE_AUDITOR = "auditor"
ROLES = {ROLE_SYSTEM, ROLE_REVIEWER, ROLE_SUPERVISOR, ROLE_AUDITOR}
PERSONNEL_ROLES = {ROLE_REVIEWER, ROLE_SUPERVISOR, ROLE_AUDITOR}
# 可执行确认、冻结、移送、申诉处理的人员角色（审计员全程只读）
REVIEW_ROLES = {ROLE_REVIEWER, ROLE_SUPERVISOR}

EVENT_TYPES = {"text", "image_summary", "audio_transcript", "account_relation"}

# 入库载荷中禁止出现的字段：原始私密素材一律留在来源系统，
# 本服务只接收定位信息、摘要与内容哈希。
FORBIDDEN_EVENT_FIELDS = {"raw_content", "raw_media", "original", "content", "media"}


class DomainError(Exception):
    """业务规则冲突，携带 HTTP 状态码与稳定错误码。"""

    def __init__(self, code, message, http_status=409):
        super().__init__(message)
        self.code = code
        self.message = message
        self.http_status = http_status


def bad_request(code, message):
    return DomainError(code, message, 400)


def forbidden(code, message):
    return DomainError(code, message, 403)


def not_found(code, message):
    return DomainError(code, message, 404)


def conflict(code, message):
    return DomainError(code, message, 409)
