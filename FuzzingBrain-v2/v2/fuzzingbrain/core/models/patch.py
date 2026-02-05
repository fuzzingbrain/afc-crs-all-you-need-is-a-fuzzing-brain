"""
Patch Model - Bug fix patch
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, List

from ..utils import generate_id


@dataclass
class Patch:
    """
    Patch represents a bug fix for a vulnerability.

    A successful patch must:
    1. Apply cleanly to the codebase
    2. Compile successfully
    3. Pass POV check (no longer triggers the bug)
    4. Pass regression tests (if provided)
    """

    # Identifiers
    patch_id: str = field(default_factory=generate_id)
    task_id: str = ""  # Required: which task does this patch belong to
    pov_id: Optional[str] = None  # Optional: which POV is this patch fixing

    # Patch content
    patch_content: Optional[str] = None  # The actual diff content

    # Description
    description: Optional[str] = None
    pov_detail: Optional[str] = None  # User-provided POV detail

    # Verification results
    apply_check: bool = False  # Can the patch be applied?
    compilation_check: bool = False  # Does it compile?
    pov_check: bool = False  # Does it pass POV test?
    test_check: bool = False  # Does it pass regression tests?

    # Status
    is_active: bool = True  # For deduplication

    # LLM context
    msg_history: List[dict] = field(default_factory=list)

    # Timestamps
    created_at: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> dict:
        """Convert to dictionary for MongoDB storage"""
        return {
            "_id": self.patch_id,
            "patch_id": self.patch_id,
            "task_id": self.task_id,
            "pov_id": self.pov_id,
            "patch_content": self.patch_content,
            "description": self.description,
            "pov_detail": self.pov_detail,
            "apply_check": self.apply_check,
            "compilation_check": self.compilation_check,
            "pov_check": self.pov_check,
            "test_check": self.test_check,
            "is_active": self.is_active,
            "msg_history": self.msg_history,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Patch":
        """Create Patch from dictionary"""
        return cls(
            patch_id=data.get("patch_id", data.get("_id", generate_id())),
            task_id=data.get("task_id", ""),
            pov_id=data.get("pov_id"),
            patch_content=data.get("patch_content"),
            description=data.get("description"),
            pov_detail=data.get("pov_detail"),
            apply_check=data.get("apply_check", False),
            compilation_check=data.get("compilation_check", False),
            pov_check=data.get("pov_check", False),
            test_check=data.get("test_check", False),
            is_active=data.get("is_active", True),
            msg_history=data.get("msg_history", []),
            created_at=data.get("created_at", datetime.now()),
        )

    @property
    def is_valid(self) -> bool:
        """Check if patch passes all verification"""
        return (
            self.apply_check and
            self.compilation_check and
            self.pov_check and
            self.test_check
        )

    @property
    def passes_basic_checks(self) -> bool:
        """Check if patch passes basic checks (apply + compile)"""
        return self.apply_check and self.compilation_check
