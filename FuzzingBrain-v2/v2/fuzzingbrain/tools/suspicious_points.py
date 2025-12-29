"""
Suspicious Points Tools

Tools for AI Agent to create, update, and query suspicious points.
These tools wrap the AnalysisClient methods for use with LLM function calling.
"""

from typing import Any, Dict, List, Optional
from ..analyzer import AnalysisClient


class SuspiciousPointTools:
    """
    Tools for managing suspicious points.

    Used by AI Agent to:
    1. Create suspicious points when potential vulnerabilities are found
    2. Update suspicious points after verification
    3. List and query suspicious points
    """

    def __init__(self, client: AnalysisClient):
        """
        Initialize with an AnalysisClient.

        Args:
            client: Connected AnalysisClient instance
        """
        self.client = client

    def create_suspicious_point(
        self,
        function_name: str,
        description: str,
        vuln_type: str,
        score: float = 0.5,
        important_controlflow: List[Dict] = None,
    ) -> Dict[str, Any]:
        """
        Create a new suspicious point.

        Call this when you identify a potential vulnerability in the code.
        Use control flow descriptions instead of line numbers.

        Args:
            function_name: The function containing the suspicious code
            description: Detailed description of the potential vulnerability.
                        Describe using control flow, not line numbers.
                        Example: "The length parameter from user input flows into
                        memcpy without bounds checking after the if-else branch"
            vuln_type: Type of vulnerability. One of:
                - buffer-overflow
                - use-after-free
                - integer-overflow
                - null-pointer-dereference
                - format-string
                - double-free
                - uninitialized-memory
                - out-of-bounds-read
                - out-of-bounds-write
            score: Confidence score (0.0-1.0). Higher means more likely to be real.
                - 0.8-1.0: Very confident, clear vulnerability pattern
                - 0.5-0.8: Moderate confidence, needs verification
                - 0.0-0.5: Low confidence, suspicious but uncertain
            important_controlflow: List of related functions/variables that affect this bug.
                Format: [{"type": "function"|"variable", "name": "xxx", "location": "description"}]

        Returns:
            {"id": "xxx", "created": True} on success

        Example:
            create_suspicious_point(
                function_name="png_handle_iCCP",
                description="profile_length from chunk data is used in memcpy without validation",
                vuln_type="buffer-overflow",
                score=0.8,
                important_controlflow=[
                    {"type": "variable", "name": "profile_length", "location": "read from png chunk"},
                    {"type": "function", "name": "png_crc_read", "location": "caller that provides data"}
                ]
            )
        """
        return self.client.create_suspicious_point(
            function_name=function_name,
            description=description,
            vuln_type=vuln_type,
            score=score,
            important_controlflow=important_controlflow or [],
        )

    def update_suspicious_point(
        self,
        suspicious_point_id: str,
        is_checked: bool = None,
        is_real: bool = None,
        is_important: bool = None,
        score: float = None,
        verification_notes: str = None,
    ) -> Dict[str, Any]:
        """
        Update a suspicious point after verification.

        Call this after analyzing a suspicious point to mark it as verified.

        Args:
            suspicious_point_id: The ID of the suspicious point to update
            is_checked: Set to True when verification is complete
            is_real: Set to True if confirmed as real vulnerability, False if false positive
            is_important: Set to True if this is a high-priority vulnerability
            score: Updated confidence score based on analysis
            verification_notes: Notes explaining the verification result.
                Example: "Confirmed: no bounds check before memcpy, attacker-controlled length"
                Example: "False positive: length is validated in caller function png_read_chunk"

        Returns:
            {"updated": True} on success

        Example (confirming a real bug):
            update_suspicious_point(
                suspicious_point_id="abc123",
                is_checked=True,
                is_real=True,
                is_important=True,
                score=0.95,
                verification_notes="Confirmed buffer overflow: profile_length can exceed buffer size"
            )

        Example (marking as false positive):
            update_suspicious_point(
                suspicious_point_id="abc123",
                is_checked=True,
                is_real=False,
                verification_notes="False positive: png_read_chunk validates length before calling"
            )
        """
        return self.client.update_suspicious_point(
            sp_id=suspicious_point_id,
            is_checked=is_checked,
            is_real=is_real,
            is_important=is_important,
            score=score,
            verification_notes=verification_notes,
        )

    def list_suspicious_points(
        self,
        filter_unchecked: bool = False,
        filter_real: bool = False,
        filter_important: bool = False,
    ) -> Dict[str, Any]:
        """
        List suspicious points for the current task.

        Args:
            filter_unchecked: If True, only return points that haven't been verified yet
            filter_real: If True, only return confirmed real vulnerabilities
            filter_important: If True, only return high-priority points

        Returns:
            {
                "suspicious_points": [...],  # List of suspicious point dicts
                "count": N,                  # Number of points returned
                "stats": {
                    "total": N,
                    "checked": N,
                    "unchecked": N,
                    "real": N,
                    "false_positive": N,
                    "important": N
                }
            }
        """
        return self.client.list_suspicious_points(
            filter_unchecked=filter_unchecked,
            filter_real=filter_real,
            filter_important=filter_important,
        )

    def get_suspicious_point(self, suspicious_point_id: str) -> Optional[Dict[str, Any]]:
        """
        Get details of a specific suspicious point.

        Args:
            suspicious_point_id: The ID of the suspicious point

        Returns:
            Suspicious point dict or None if not found
        """
        return self.client.get_suspicious_point(suspicious_point_id)


# Tool definitions for LLM function calling
SUSPICIOUS_POINT_TOOLS = [
    {
        "name": "create_suspicious_point",
        "description": "Create a new suspicious point when you identify a potential vulnerability in the code. Use control flow descriptions instead of line numbers.",
        "parameters": {
            "type": "object",
            "properties": {
                "function_name": {
                    "type": "string",
                    "description": "The function containing the suspicious code"
                },
                "description": {
                    "type": "string",
                    "description": "Detailed description of the potential vulnerability using control flow, not line numbers"
                },
                "vuln_type": {
                    "type": "string",
                    "enum": [
                        "buffer-overflow",
                        "use-after-free",
                        "integer-overflow",
                        "null-pointer-dereference",
                        "format-string",
                        "double-free",
                        "uninitialized-memory",
                        "out-of-bounds-read",
                        "out-of-bounds-write"
                    ],
                    "description": "Type of vulnerability"
                },
                "score": {
                    "type": "number",
                    "description": "Confidence score (0.0-1.0). Higher means more likely to be real."
                },
                "important_controlflow": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "type": {"type": "string", "enum": ["function", "variable"]},
                            "name": {"type": "string"},
                            "location": {"type": "string"}
                        }
                    },
                    "description": "List of related functions/variables that affect this bug"
                }
            },
            "required": ["function_name", "description", "vuln_type"]
        }
    },
    {
        "name": "update_suspicious_point",
        "description": "Update a suspicious point after verification. Mark it as checked and indicate if it's a real vulnerability or false positive.",
        "parameters": {
            "type": "object",
            "properties": {
                "suspicious_point_id": {
                    "type": "string",
                    "description": "The ID of the suspicious point to update"
                },
                "is_checked": {
                    "type": "boolean",
                    "description": "Set to true when verification is complete"
                },
                "is_real": {
                    "type": "boolean",
                    "description": "True if confirmed as real vulnerability, False if false positive"
                },
                "is_important": {
                    "type": "boolean",
                    "description": "True if this is a high-priority vulnerability"
                },
                "score": {
                    "type": "number",
                    "description": "Updated confidence score based on analysis"
                },
                "verification_notes": {
                    "type": "string",
                    "description": "Notes explaining the verification result"
                }
            },
            "required": ["suspicious_point_id"]
        }
    },
    {
        "name": "list_suspicious_points",
        "description": "List suspicious points for the current task with optional filters.",
        "parameters": {
            "type": "object",
            "properties": {
                "filter_unchecked": {
                    "type": "boolean",
                    "description": "Only return points that haven't been verified yet"
                },
                "filter_real": {
                    "type": "boolean",
                    "description": "Only return confirmed real vulnerabilities"
                },
                "filter_important": {
                    "type": "boolean",
                    "description": "Only return high-priority points"
                }
            }
        }
    }
]
