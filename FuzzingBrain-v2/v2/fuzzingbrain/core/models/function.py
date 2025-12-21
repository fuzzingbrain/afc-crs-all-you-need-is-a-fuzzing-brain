"""
Function Model - Extracted function metadata from source code
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


@dataclass
class Function:
    """
    Function stores extracted metadata from source code.

    Each function is stored once per task, regardless of how many
    fuzzers can reach it. The function_id is {task_id}_{name} to
    ensure uniqueness within a task.

    This model stores the static analysis results from tree-sitter
    parsing, without requiring compilation.
    """

    # Identifiers
    function_id: str = ""  # {task_id}_{name}
    task_id: str = ""

    # Function info
    name: str = ""  # Function name, e.g., "parse_config"
    file_path: str = ""  # Relative path to source file
    start_line: int = 0
    end_line: int = 0
    content: str = ""  # Full function source code

    # Optional metadata
    language: str = "c"  # Programming language

    # Timestamps
    created_at: datetime = field(default_factory=datetime.now)

    def __post_init__(self):
        """Auto-generate function_id if not set"""
        if not self.function_id and self.task_id and self.name:
            self.function_id = f"{self.task_id}_{self.name}"

    def to_dict(self) -> dict:
        """Convert to dictionary for MongoDB storage"""
        return {
            "_id": self.function_id,
            "function_id": self.function_id,
            "task_id": self.task_id,
            "name": self.name,
            "file_path": self.file_path,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "content": self.content,
            "language": self.language,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Function":
        """Create Function from dictionary"""
        return cls(
            function_id=data.get("function_id", data.get("_id", "")),
            task_id=data.get("task_id", ""),
            name=data.get("name", ""),
            file_path=data.get("file_path", ""),
            start_line=data.get("start_line", 0),
            end_line=data.get("end_line", 0),
            content=data.get("content", ""),
            language=data.get("language", "c"),
            created_at=data.get("created_at", datetime.now()),
        )
