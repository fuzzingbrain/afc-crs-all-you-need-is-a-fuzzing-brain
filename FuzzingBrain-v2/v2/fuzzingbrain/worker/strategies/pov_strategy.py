"""
POV Strategy

Finds vulnerabilities and generates Proof-of-Vulnerability (POV).

Workflow:
1. [Delta mode] Check if diff changes are reachable from fuzzer
2. Analyze code to find suspicious points
3. Verify suspicious points with AI Agent
4. Run fuzzing to trigger crashes
5. Generate POV from crashes
"""

import json
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional

from loguru import logger

from .base import BaseStrategy
from ...analysis.diff_parser import get_reachable_changes, DiffReachabilityResult
from ...core.models import SuspiciousPoint


class POVStrategy(BaseStrategy):
    """
    POV (Proof-of-Vulnerability) Strategy.

    This is the core strategy for finding vulnerabilities.
    """

    def __init__(self, executor):
        super().__init__(executor)

        # Diff path for delta mode
        self.diff_path = executor.diff_path

        # Reachability result (populated in delta mode)
        self._reachability_result: Optional[DiffReachabilityResult] = None

        # Fuzzer binary path
        self.fuzzer_binary_path = executor.fuzzer_binary_path

        # Corpus and crash directories for libFuzzer
        self.corpus_path = self.workspace_path / "corpus"
        self.crash_output_path = self.workspace_path / "crashes"

        # Ensure directories exist
        self.corpus_path.mkdir(parents=True, exist_ok=True)
        self.crash_output_path.mkdir(parents=True, exist_ok=True)

    def execute(self) -> Dict[str, Any]:
        """
        Execute POV strategy.

        Returns:
            Result dictionary with findings
        """
        self.log_info(f"Starting POV strategy for {self.fuzzer} (mode: {self.scan_mode})")

        result = {
            "strategy": "pov",
            "scan_mode": self.scan_mode,
            "reachable": True,
            "reachable_changes": [],
            "suspicious_points_found": 0,
            "suspicious_points_verified": 0,
            "crashes_found": 0,
            "povs_generated": 0,
        }

        try:
            # Step 1: Delta mode - check diff reachability
            if self.scan_mode == "delta":
                reachability = self._check_diff_reachability()
                result["reachable"] = reachability.reachable
                result["reachable_changes"] = [
                    {"function": c.function_name, "file": c.file_path, "distance": c.reachability_distance}
                    for c in reachability.reachable_changes
                ]

                if not reachability.reachable:
                    self.log_info(f"No reachable changes in diff, skipping")
                    result["skip_reason"] = "no_reachable_changes"
                    return result

                self.log_info(f"Found {len(reachability.reachable_changes)} reachable changes")

            # Step 2: Find suspicious points
            suspicious_points = self._find_suspicious_points()
            result["suspicious_points_found"] = len(suspicious_points)

            if not suspicious_points:
                self.log_info("No suspicious points found")
                return result

            # Step 3: Verify suspicious points with AI Agent
            verified_points = self._verify_suspicious_points(suspicious_points)
            result["suspicious_points_verified"] = len(verified_points)

            # Step 4: Run fuzzing
            crashes = self._run_fuzzing(verified_points)
            result["crashes_found"] = len(crashes)

            if not crashes:
                self.log_info("No crashes found during fuzzing")
                return result

            # Step 5: Generate POVs from crashes
            povs = self._generate_povs(crashes)
            result["povs_generated"] = len(povs)

            self.log_info(f"Completed: {len(povs)} POVs generated from {len(crashes)} crashes")
            return result

        except Exception as e:
            self.log_error(f"Strategy failed: {e}")
            raise

    # =========================================================================
    # Step 1: Diff Reachability (Delta Mode)
    # =========================================================================

    def _check_diff_reachability(self) -> DiffReachabilityResult:
        """
        Check if changes in diff are reachable from this fuzzer.

        Returns:
            DiffReachabilityResult with reachable changes
        """
        self.log_info(f"Checking diff reachability for fuzzer: {self.fuzzer}")

        # Check if diff file exists
        if not self.diff_path or not self.diff_path.exists():
            self.log_warning(f"Diff file not found: {self.diff_path}")
            return DiffReachabilityResult(reachable=False)

        # Read diff content
        try:
            diff_content = self.diff_path.read_text(encoding='utf-8', errors='replace')
        except Exception as e:
            self.log_error(f"Failed to read diff file: {e}")
            return DiffReachabilityResult(reachable=False)

        if not diff_content.strip():
            self.log_warning("Diff file is empty")
            return DiffReachabilityResult(reachable=False)

        self.log_debug(f"Read diff file: {len(diff_content)} bytes")

        # Check if Analysis Server is available
        analysis_client = self.get_analysis_client()
        if not analysis_client:
            self.log_error("Analysis Server not available, cannot check reachability")
            # Return optimistic result - assume reachable if we can't check
            return DiffReachabilityResult(reachable=True)

        # Analyze diff reachability
        result = get_reachable_changes(diff_content, self.fuzzer, analysis_client)
        self._reachability_result = result

        # Save report
        self._save_reachability_report(result)

        return result

    def _save_reachability_report(self, result: DiffReachabilityResult) -> None:
        """Save diff reachability report to results directory."""
        report = {
            "timestamp": datetime.now().isoformat(),
            "task_id": self.task_id,
            "fuzzer": self.fuzzer,
            "sanitizer": self.sanitizer,
            "scan_mode": self.scan_mode,
            "diff_path": str(self.diff_path),
            "reachable": result.reachable,
            "summary": result.summary,
            "total_changed_functions": result.total_changed_functions,
            "changed_files": result.changed_files,
            "reachable_changes": [
                {
                    "function": c.function_name,
                    "file": c.file_path,
                    "function_file": c.function_file,
                    "lines": f"{c.line_start}-{c.line_end}",
                    "changed_lines": c.changed_lines,
                    "distance": c.reachability_distance,
                    "diff_content": c.diff_content,
                }
                for c in result.reachable_changes
            ],
            "unreachable_functions": result.unreachable_functions,
        }

        report_path = self.results_path / "diff_reachability_report.json"
        try:
            with open(report_path, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            self.log_info(f"Saved reachability report to: {report_path}")
        except Exception as e:
            self.log_error(f"Failed to save reachability report: {e}")

    # =========================================================================
    # Step 2: Find Suspicious Points
    # =========================================================================

    def _find_suspicious_points(self) -> List[SuspiciousPoint]:
        """
        Find suspicious points in code.

        For delta mode: Focus on reachable changed functions.
        For full mode: Analyze all reachable functions.

        Returns:
            List of SuspiciousPoint objects
        """
        self.log_info("Finding suspicious points...")

        suspicious_points = []

        if self.scan_mode == "delta" and self._reachability_result:
            # Delta mode: analyze reachable changes
            for change in self._reachability_result.reachable_changes:
                points = self._analyze_function_for_vulnerabilities(
                    function_name=change.function_name,
                    file_path=change.function_file,
                    diff_content=change.diff_content,
                )
                suspicious_points.extend(points)
        else:
            # Full mode: TODO - analyze all functions reachable from fuzzer
            self.log_warning("Full scan suspicious point analysis not yet implemented")

        self.log_info(f"Found {len(suspicious_points)} suspicious points")
        return suspicious_points

    def _analyze_function_for_vulnerabilities(
        self,
        function_name: str,
        file_path: str,
        diff_content: str = None,
    ) -> List[SuspiciousPoint]:
        """
        Analyze a function for potential vulnerabilities.

        Uses AI to identify suspicious code patterns.

        Args:
            function_name: Function to analyze
            file_path: File containing the function
            diff_content: Optional diff content for context

        Returns:
            List of SuspiciousPoint objects
        """
        # TODO: Implement AI-based vulnerability analysis
        # This should:
        # 1. Get function source code
        # 2. Send to LLM for analysis
        # 3. Parse LLM response into SuspiciousPoint objects

        self.log_debug(f"Analyzing function: {function_name} in {file_path}")

        # Placeholder - return empty list for now
        return []

    # =========================================================================
    # Step 3: Verify Suspicious Points
    # =========================================================================

    def _verify_suspicious_points(
        self, suspicious_points: List[SuspiciousPoint]
    ) -> List[SuspiciousPoint]:
        """
        Verify suspicious points with AI Agent.

        The agent performs deeper analysis to determine if each point
        is likely a real vulnerability.

        Args:
            suspicious_points: List of points to verify

        Returns:
            List of verified (likely real) suspicious points
        """
        self.log_info(f"Verifying {len(suspicious_points)} suspicious points...")

        verified = []

        for point in suspicious_points:
            # TODO: Implement AI verification
            # This should:
            # 1. Get more context (callers, callees, data flow)
            # 2. Ask AI to verify if the bug is real
            # 3. Mark point as verified or not

            # Placeholder - assume all are verified
            verified.append(point)

        self.log_info(f"Verified {len(verified)} suspicious points")
        return verified

    # =========================================================================
    # Step 4: Run Fuzzing
    # =========================================================================

    def _run_fuzzing(
        self, suspicious_points: List[SuspiciousPoint] = None
    ) -> List[Path]:
        """
        Run libFuzzer to trigger crashes.

        Args:
            suspicious_points: Optional list of points to guide fuzzing

        Returns:
            List of crash file paths
        """
        self.log_info("Running fuzzing...")

        if not self.fuzzer_binary_path:
            self.log_error("No fuzzer binary path provided")
            return []

        fuzzer_path = Path(self.fuzzer_binary_path)
        if not fuzzer_path.exists():
            self.log_error(f"Fuzzer binary not found: {fuzzer_path}")
            return []

        # libFuzzer arguments
        args = [
            str(fuzzer_path),
            str(self.corpus_path),
            f"-artifact_prefix={self.crash_output_path}/",
            "-max_total_time=60",  # 60 seconds for now
            "-print_final_stats=1",
        ]

        self.log_info(f"Running: {' '.join(args)}")

        try:
            result = subprocess.run(
                args,
                capture_output=True,
                text=True,
                timeout=120,  # 2 minute timeout
                cwd=str(self.workspace_path),
            )

            # Log output
            if result.stdout:
                self.log_debug(f"Fuzzer stdout:\n{result.stdout[-2000:]}")  # Last 2000 chars
            if result.stderr:
                self.log_debug(f"Fuzzer stderr:\n{result.stderr[-2000:]}")

        except subprocess.TimeoutExpired:
            self.log_warning("Fuzzer timeout")
        except Exception as e:
            self.log_error(f"Fuzzer failed: {e}")

        # Collect crash files
        crashes = list(self.crash_output_path.glob("crash-*"))
        crashes.extend(self.crash_output_path.glob("oom-*"))
        crashes.extend(self.crash_output_path.glob("timeout-*"))

        self.log_info(f"Found {len(crashes)} crash files")
        return crashes

    # =========================================================================
    # Step 5: Generate POVs
    # =========================================================================

    def _generate_povs(self, crashes: List[Path]) -> List[str]:
        """
        Generate POV from crash files.

        Args:
            crashes: List of crash file paths

        Returns:
            List of POV IDs
        """
        self.log_info(f"Generating POVs from {len(crashes)} crashes...")

        pov_ids = []

        for crash_file in crashes:
            try:
                pov_id = self._process_crash(crash_file)
                if pov_id:
                    pov_ids.append(pov_id)
            except Exception as e:
                self.log_error(f"Failed to process crash {crash_file}: {e}")

        self.log_info(f"Generated {len(pov_ids)} POVs")
        return pov_ids

    def _process_crash(self, crash_file: Path) -> Optional[str]:
        """
        Process a single crash file into a POV.

        Args:
            crash_file: Path to crash file

        Returns:
            POV ID or None
        """
        # TODO: Implement crash processing
        # This should:
        # 1. Read crash input
        # 2. Verify reproducibility
        # 3. Minimize crash input
        # 4. Extract crash info (stack trace, etc.)
        # 5. Create POV record in database

        self.log_debug(f"Processing crash: {crash_file}")

        # Placeholder
        return None

    # =========================================================================
    # Properties
    # =========================================================================

    @property
    def reachable_changes(self) -> List:
        """Get the list of reachable changes (after running delta check)."""
        if self._reachability_result:
            return self._reachability_result.reachable_changes
        return []
