"""
Code Coverage Analyzer

Provides coverage and control flow analysis for fuzzer inputs.
Supports both C/C++ (via LLVM coverage) and Java (via JaCoCo) projects.
"""
import os
import shutil
import subprocess
import uuid
from typing import Tuple, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from common.config import StrategyConfig
    from common.logging.logger import StrategyLogger


class CoverageAnalyzer:
    """
    Analyzes code coverage and extracts control flow information

    Usage:
        analyzer = CoverageAnalyzer(config, logger)
        feedback = analyzer.get_coverage_feedback(blob_path)
        if feedback:
            prompt += feedback
    """

    def __init__(self, config: 'StrategyConfig', logger: 'StrategyLogger'):
        """
        Initialize coverage analyzer

        Args:
            config: Strategy configuration
            logger: Logger instance
        """
        self.config = config
        self.logger = logger
        self.is_c_project = config.language.startswith('c')

    def get_coverage_feedback(self, blob_path: str) -> str:
        """
        Get coverage feedback for the given test input

        Args:
            blob_path: Path to the test blob file

        Returns:
            Formatted coverage feedback string for LLM prompt,
            or empty string if coverage analysis fails or is disabled
        """
        if not hasattr(self.config, 'use_control_flow') or not self.config.use_control_flow:
            return ""

        if self.is_c_project:
            control_flow = self._analyze_c_coverage(blob_path)
        else:
            control_flow = self._analyze_java_coverage(blob_path)

        if not control_flow:
            return ""

        return self._format_coverage_feedback(control_flow)

    def _format_coverage_feedback(self, control_flow: str) -> str:
        """
        Format and compress control flow information for LLM feedback

        Args:
            control_flow: Raw control flow text

        Returns:
            Formatted feedback message
        """
        cf_lines = control_flow.splitlines()

        if len(cf_lines) > 200:
            compressed_cf = (
                "\n".join(cf_lines[:100]) +
                "\n...[truncated]...\n" +
                "\n".join(cf_lines[-100:])
            )
        else:
            compressed_cf = control_flow

        return (
            f"\n\nThe following shows the executed code path of the fuzzer with input x.bin. "
            f"You should generate a new x.bin to execute a different code path\n{compressed_cf}"
        )

    def _analyze_c_coverage(self, blob_path: str) -> str:
        """
        Analyze coverage for C/C++ project

        Args:
            blob_path: Path to test blob

        Returns:
            Control flow text or empty string on failure
        """
        success, lcov_path, msg = self._run_c_coverage_fuzzer(blob_path)

        if not success:
            self.logger.warning(f"C coverage fuzzer failed: {msg}")
            return ""

        project_src_dir = os.path.join(self.config.project_dir, self.config.focus)
        control_flow = self._extract_c_control_flow(lcov_path, project_src_dir)

        return control_flow

    def _run_c_coverage_fuzzer(self, blob_path: str) -> Tuple[bool, str, str]:
        """
        Execute coverage build of libFuzzer target and produce coverage.lcov

        Args:
            blob_path: Path to test blob

        Returns:
            (success, lcov_path, message)
        """
        try:
            cov_fuzzer_path = self.config.fuzzer_path + "-coverage"
            self.logger.log(f"[coverage] fuzzer: {cov_fuzzer_path}")
            self.logger.log(f"[coverage] input blob: {blob_path}")

            fuzzer_dir = os.path.dirname(cov_fuzzer_path)
            fuzzer_name = os.path.basename(cov_fuzzer_path)
            out_dir = os.path.join(fuzzer_dir, "xp0")

            os.makedirs(out_dir, exist_ok=True)
            lcov_host = os.path.join(out_dir, "coverage.lcov")

            unique_blob = f"x_{uuid.uuid4().hex[:8]}.bin"
            host_blob = os.path.join(out_dir, unique_blob)
            shutil.copy(blob_path, host_blob)
            self.logger.log(f"[coverage] blob copied to {host_blob}")

            docker_run = [
                "docker", "run", "--rm", "--platform", "linux/amd64",
                "-e", "FUZZING_ENGINE=libfuzzer",
                "-e", "ARCHITECTURE=x86_64",
                "-e", "LLVM_PROFILE_FILE=/out/coverage.profraw",
                "-v", f"{out_dir}:/out",
                f"aixcc-afc/{self.config.project_name}",
                f"/out/{fuzzer_name}",
                "-runs=1",
                f"/out/{unique_blob}",
            ]

            self.logger.log("[coverage] " + " ".join(docker_run))
            res = subprocess.run(docker_run, capture_output=True, text=True, timeout=120)
            self.logger.log(res.stdout)
            if res.stderr:
                self.logger.log(res.stderr)

            if res.returncode not in (0, 77, 99):
                return False, lcov_host, f"fuzzer exited with code {res.returncode}"

            profraw_host = os.path.join(out_dir, "coverage.profraw")
            if not os.path.exists(profraw_host) or os.path.getsize(profraw_host) == 0:
                return False, lcov_host, "coverage.profraw was not produced"

            merge_and_export = (
                "llvm-profdata merge -sparse /out/coverage.profraw -o /out/coverage.profdata && "
                f"llvm-cov export /out/{fuzzer_name} "
                "-instr-profile=/out/coverage.profdata "
                "-format=lcov > /out/coverage.lcov"
            )

            docker_cov = [
                "docker", "run", "--rm", "--platform", "linux/amd64",
                "-v", f"{out_dir}:/out",
                f"aixcc-afc/{self.config.project_name}",
                "bash", "-c", merge_and_export,
            ]
            self.logger.log("[coverage] " + " ".join(docker_cov))
            res2 = subprocess.run(docker_cov, capture_output=True, text=True, timeout=120)
            if res2.stderr:
                self.logger.log(res2.stderr)
            if res2.returncode != 0:
                return False, lcov_host, "llvm-profdata/llvm-cov failed"

            if not os.path.exists(lcov_host):
                return False, lcov_host, "coverage.lcov was not created"
            self.logger.log(f"[coverage] coverage.lcov size={os.path.getsize(lcov_host)} bytes")

            return True, lcov_host, "coverage.lcov generated successfully"

        except subprocess.TimeoutExpired:
            self.logger.warning("[coverage] execution timed out")
            return False, "", "Timeout"
        except Exception as exc:
            self.logger.error(f"[coverage] error: {exc}")
            return False, "", str(exc)

    def _extract_c_control_flow(self, lcov_path: str, project_src_dir: str) -> str:
        """
        Extract control flow from LCOV data for C/C++ project

        Args:
            lcov_path: Path to coverage.lcov file
            project_src_dir: Root of project source tree

        Returns:
            Control flow text or empty string on failure
        """
        self.logger.log(f"[extract_control_flow_for_c] lcov: {lcov_path}")
        self.logger.log(f"[extract_control_flow_for_c] src-root: {project_src_dir}")

        out_dir_x = os.path.dirname(lcov_path)

        target_files = self._get_diff_target_files(project_src_dir, out_dir_x)
        self.logger.log(f"[extract_control_flow_for_c] target_files: {target_files}")

        helper_script = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "jeff", "c_coverage.py"
        )
        if not os.path.exists(helper_script):
            helper_script = "c_coverage.py"

        cmd = [
            "python3", helper_script,
            "--lcov", lcov_path,
            "--src-root", project_src_dir,
            "--project-name", self.config.project_name,
        ]
        if target_files:
            cmd.extend(["--files", *target_files])

        try:
            self.logger.log(f"[extract_control_flow_for_c] Running: {' '.join(cmd)}")
            result = subprocess.run(
                cmd,
                cwd=out_dir_x,
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.stdout:
                self.logger.log(f"[c_coverage] stdout:\n{result.stdout}")
            if result.stderr:
                self.logger.log(f"[c_coverage] stderr:\n{result.stderr}")

            if result.returncode != 0:
                self.logger.warning(f"[extract_control_flow_for_c] helper exited with {result.returncode}")
                return ""

            return result.stdout

        except subprocess.TimeoutExpired:
            self.logger.warning("[extract_control_flow_for_c] c_coverage.py timed out")
            return ""
        except Exception as exc:
            self.logger.error(f"[extract_control_flow_for_c] error: {exc}")
            return ""

    def _get_diff_target_files(self, project_src_dir: str, out_dir_x: str) -> list:
        """
        Determine files changed by diff analysis

        Args:
            project_src_dir: Project source directory
            out_dir_x: Output directory

        Returns:
            List of target file basenames
        """
        try:
            from common.utils import extract_diff_functions_using_funtarget

            diff_funcs = extract_diff_functions_using_funtarget(project_src_dir, out_dir_x) or []
            target_files = sorted(
                {os.path.basename(d.get("file", "")) for d in diff_funcs if d.get("file")}
            )
            return target_files
        except Exception as e:
            self.logger.warning(f"Failed to extract diff functions: {e}")
            return []

    def _analyze_java_coverage(self, blob_path: str) -> str:
        """
        Analyze coverage for Java project

        Args:
            blob_path: Path to test blob

        Returns:
            Control flow text or empty string on failure
        """
        fuzz_dir = os.path.dirname(self.config.fuzzer_path)
        coverage_exec_dir = os.path.join(fuzz_dir, "xp0")
        project_jar = f"{self.config.project_name}.jar"
        project_src_dir = os.path.join(self.config.project_dir, self.config.focus)

        control_flow = self._extract_java_control_flow(
            project_src_dir,
            project_jar,
            coverage_exec_dir
        )

        return control_flow

    def _extract_java_control_flow(
        self,
        project_src_dir: str,
        project_jar: str,
        coverage_exec_dir: str
    ) -> str:
        """
        Extract control flow from Java coverage.exec

        Args:
            project_src_dir: Project source directory
            project_jar: Project JAR filename
            coverage_exec_dir: Directory containing coverage.exec

        Returns:
            Control flow text or empty string on failure
        """
        self.logger.log(f"project_src_dir: {project_src_dir}")
        self.logger.log(f"project_jar: {project_jar}")
        self.logger.log(f"coverage_exec_dir: {coverage_exec_dir}")

        jar_path = os.path.join(coverage_exec_dir, project_jar)
        if not os.path.isfile(jar_path):
            fallback = self._pick_fallback_jar(coverage_exec_dir)
            if fallback:
                self.logger.log(
                    f"[java_coverage] {project_jar} not found - "
                    f"using fallback jar {fallback}"
                )
                jar_path = fallback
            else:
                self.logger.warning("[java_coverage] no suitable *.jar found; aborting")
                return ""

        helper_script = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "jeff", "java_coverage.py"
        )
        if not os.path.exists(helper_script):
            helper_script = "java_coverage.py"

        coverage_exec_path = os.path.join(coverage_exec_dir, "coverage.exec")

        try:
            cmd = [
                "python3",
                helper_script,
                coverage_exec_path,
                jar_path,
                project_src_dir,
            ]
            self.logger.log("extract_control_flow_from_coverage_exec CMD: " + " ".join(cmd))

            result = subprocess.run(
                cmd,
                cwd=coverage_exec_dir,
                capture_output=True,
                text=True,
                timeout=30,
            )

            self.logger.log(f"extract_control_flow_from_coverage_exec stdout: {result.stdout}")
            if result.stderr:
                self.logger.log(f"Python code execution stderr: {result.stderr}")

            return result.stdout

        except subprocess.TimeoutExpired:
            self.logger.warning("Python code execution timed out")
            return ""
        except Exception as e:
            self.logger.error(f"Error running Python code: {str(e)}")
            return ""

    def _pick_fallback_jar(self, directory: str) -> Optional[str]:
        """
        Find a fallback JAR file in the directory

        Args:
            directory: Directory to search

        Returns:
            Path to JAR file or None
        """
        try:
            for fname in os.listdir(directory):
                if fname.endswith(".jar"):
                    return os.path.join(directory, fname)
        except Exception:
            pass
        return None
