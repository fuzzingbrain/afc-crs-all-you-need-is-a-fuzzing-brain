"""
SuspiciousPoint Model - 可疑点

可疑点是介于行级和函数级之间的漏洞分析粒度。
每个可疑点代表一个潜在的漏洞位置，需要通过 AI Agent 验证。
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, List, Dict
import uuid


@dataclass
class ControlFlowItem:
    """
    控制流相关项，可以是函数或变量
    """
    type: str  # "function" | "variable"
    name: str
    location: str  # 位置描述


@dataclass
class SuspiciousPoint:
    """
    可疑点 - 潜在漏洞位置

    可疑点分析是重构后 CRS 的精髓。以前的 CRS 采用函数级分析，
    可能会忽略同一函数中的多个 bug，或检测不到细节性 bug。
    一个可疑点就是一次行级分析。
    """

    # 标识符
    suspicious_point_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    task_id: str = ""  # 属于哪个 task
    function_name: str = ""  # 属于哪个函数

    # 描述（不用具体行号，用控制流描述，因为 LLM 不擅长生成行号）
    description: str = ""

    # 漏洞类型
    vuln_type: str = ""  # buffer-overflow, use-after-free, integer-overflow, null-pointer, etc.

    # 验证状态
    is_checked: bool = False  # 是否已被 LLM 二次验证
    is_real: bool = False  # 如果 Agent 认为是真实 bug，则为 True

    # 优先级
    score: float = 0.0  # 分数 (0.0-1.0)，用于队列排序
    is_important: bool = False  # 如果被认定为高可能性 bug，直接进入队首

    # 相关控制流信息
    important_controlflow: List[Dict] = field(default_factory=list)
    # 格式: [{"type": "function"|"variable", "name": "xxx", "location": "xxx"}, ...]

    # 验证备注
    verification_notes: Optional[str] = None

    # 时间戳
    created_at: datetime = field(default_factory=datetime.now)
    checked_at: Optional[datetime] = None

    def to_dict(self) -> dict:
        """转换为字典，用于 MongoDB 存储"""
        return {
            "_id": self.suspicious_point_id,
            "suspicious_point_id": self.suspicious_point_id,
            "task_id": self.task_id,
            "function_name": self.function_name,
            "description": self.description,
            "vuln_type": self.vuln_type,
            "is_checked": self.is_checked,
            "is_real": self.is_real,
            "score": self.score,
            "is_important": self.is_important,
            "important_controlflow": self.important_controlflow,
            "verification_notes": self.verification_notes,
            "created_at": self.created_at,
            "checked_at": self.checked_at,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "SuspiciousPoint":
        """从字典创建 SuspiciousPoint"""
        return cls(
            suspicious_point_id=data.get("suspicious_point_id", data.get("_id", str(uuid.uuid4()))),
            task_id=data.get("task_id", ""),
            function_name=data.get("function_name", ""),
            description=data.get("description", ""),
            vuln_type=data.get("vuln_type", ""),
            is_checked=data.get("is_checked", False),
            is_real=data.get("is_real", False),
            score=data.get("score", 0.0),
            is_important=data.get("is_important", False),
            important_controlflow=data.get("important_controlflow", []),
            verification_notes=data.get("verification_notes"),
            created_at=data.get("created_at", datetime.now()),
            checked_at=data.get("checked_at"),
        )

    def mark_checked(self, is_real: bool, notes: str = None):
        """标记为已验证"""
        self.is_checked = True
        self.is_real = is_real
        self.checked_at = datetime.now()
        if notes:
            self.verification_notes = notes

    def mark_important(self):
        """标记为重要（高优先级）"""
        self.is_important = True
