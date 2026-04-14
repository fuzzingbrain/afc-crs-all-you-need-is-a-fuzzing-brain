#!/usr/bin/env python3
"""AS0 Full Strategy - full-scan POV generation.

Inherits the multi-phase POV loop from :class:`AS0DeltaStrategy` but
swaps the input signal: instead of pulling a commit diff, full-scan
mode reads either a ``suspected_vulns.json`` file (hand-curated vulns
for the task) or security-analyser findings and drives POV generation
against each candidate.

This is a deliberately thin subclass — it reuses ``_do_pov_phase_0``
(the blob / fuzzer / retry loop) and only customises the prompt
generation for each candidate record.
"""
from __future__ import annotations

import os
import sys
from typing import Any, Dict, Tuple

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from common.prompts.builder import create_fullscan_prompt, create_security_finding_prompt
from common.task.loader import load_security_findings, load_suspected_vulns
from strategies.as0.delta import AS0DeltaStrategy


class AS0FullStrategy(AS0DeltaStrategy):
    """AS0 Full Strategy: drive POVs from suspected-vulns / security-findings JSON."""

    def get_strategy_name(self) -> str:
        return "as0_full"

    def execute_core_logic(self) -> bool:
        """Full-scan variant of the core loop.

        * Find the fuzzer source once.
        * Prefer security-analyser findings when present; fall back to
          ``suspected_vulns.json``.
        * For each candidate, build a candidate-specific prompt and
          hand it to the shared Phase 0 blob / fuzzer / retry loop.
        """
        self.logger.log("Starting AS0 full-scan POV generation")

        self.fuzzer_code = self.find_fuzzer_source()
        if not self.fuzzer_code:
            self.logger.error("Failed to find fuzzer source code")
            return False

        # Full scan has no commit; leave commit_diff empty so existing
        # helper methods that reference it don't crash.
        self.commit_diff = ""

        findings = load_security_findings(self.config.project_dir)
        if findings:
            self.logger.log(f"Loaded {len(findings)} security findings")
            return self._drive_from_findings(findings)

        suspected = load_suspected_vulns(self.config.project_dir)
        if suspected:
            self.logger.log(f"Loaded {len(suspected)} suspected vulnerabilities")
            return self._drive_from_suspected(suspected)

        self.logger.warning("No full-scan inputs found (no findings, no suspected_vulns.json)")
        return False

    def _drive_from_findings(self, findings: list) -> bool:
        for i, finding in enumerate(findings, start=1):
            self.logger.log(f"Finding {i}/{len(findings)}: {finding.get('vulnerability_type', '?')}")
            prompt = create_security_finding_prompt(
                fuzzer_code=self.fuzzer_code,
                finding=finding,
                sanitizer=self.config.sanitizer,
                language=self.config.language,
            )
            success, _ = self._do_pov_phase_0(prompt)
            if success:
                return True
        return False

    def _drive_from_suspected(self, suspected: list) -> bool:
        for i, record in enumerate(suspected, start=1):
            self.logger.log(f"Suspected vuln {i}/{len(suspected)}: {record.get('filePath', '?')}")
            prompt = create_fullscan_prompt(self.fuzzer_code, record)
            success, _ = self._do_pov_phase_0(prompt)
            if success:
                return True
        return False
