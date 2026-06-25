# SPDX-License-Identifier: Apache-2.0
"""Control-plane domain models (mirror the tables in ``schema.sql``)."""

from .sp import SPStatus, SuspiciousPoint, Verdict

__all__ = ["SPStatus", "SuspiciousPoint", "Verdict"]
