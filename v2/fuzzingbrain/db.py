# SPDX-License-Identifier: Apache-2.0
"""Control-plane access — the single source of truth.

Thin accessor over the relational schema in ``schema.sql``. The orchestrator
and skills talk to program state ONLY through this layer; nothing keeps state
in scattered files. Stubbed interface for now; a PostgreSQL implementation
(reusing the existing o2 infra, per fuzzdb) lands next.
"""

from __future__ import annotations

from typing import Protocol


class Unit(Protocol):
    """A logic-group work unit as the orchestrator sees it."""

    id: str
    pipeline_stage: str
    pipeline_status: str
    pipeline_attempts: int


class Store(Protocol):
    """Control-plane operations the orchestrator depends on."""

    def next_units(self, limit: int) -> list[Unit]:
        """Pending units whose stage is neither done nor parked."""
        ...

    def advance(self, unit: Unit, *, stage: str, passed: bool, note: str) -> None:
        """Move a unit to ``stage`` and record the transition + attempt count."""
        ...
