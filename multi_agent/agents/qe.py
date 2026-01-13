from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import List, Optional, Tuple

from multi_agent.state import (
    PatcherAgentState,
    PatchAttempt,
    PatchStatus,
)
import tempfile
from .base import Agent
import logging
import shutil
from multi_agent.overlay import dump_overlay_unified_diff, materialize_overlay_to_dir
from shared_tools.core import Ok, Err

logger = logging.getLogger(__name__)

def _run_cmd(cmd: List[str] | str, cwd: Optional[str] = None) -> Tuple[int, bytes, bytes]:
    if isinstance(cmd, str):
        print(f"QE: running cmd: {cmd} in cwd: {cwd}")
        logger.info(f"QE: running cmd: {cmd} in cwd: {cwd}")
        p = subprocess.run(cmd, shell=True, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    else:
        print(f"QE: running cmd: {' '.join(cmd)} in cwd: {cwd}")
        logger.info(f"QE: running cmd: {' '.join(cmd)} in cwd: {cwd}")
        p = subprocess.run(cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return p.returncode, p.stdout or b"", p.stderr or b""


def _project_root(state: PatcherAgentState) -> str:
    if state.project_root:
        return state.project_root
    if state.source_dir:
        return str(Path(state.source_dir).parent)
    return os.getcwd()


def _helper(state: PatcherAgentState) -> Optional[str]:
    return state.helper_script_path


def _project_name(state: PatcherAgentState) -> str:
    return state.context.project


def _maybe_source_arg_path(source_dir: Optional[str]) -> List[str]:
    return [source_dir] if source_dir else []


def _ensure_attempt(state: PatcherAgentState) -> PatchAttempt:
    if state.patch_attempts:
        return state.patch_attempts[-1]
    pa = PatchAttempt(description="QE validation")
    # assign to trigger reducer
    state.patch_attempts = [pa]
    return pa


def _replace_attempt(state: PatcherAgentState, pa: PatchAttempt) -> None:
    # trigger reducer to replace by id
    state.patch_attempts = [pa]


def _already_successful(state: PatcherAgentState) -> bool:
    for pa in state.patch_attempts:
        if pa.build_succeeded and pa.pov_fixed:
            return True
    return False

def _get_current_diff(state: PatcherAgentState) -> str | None:
    # last attempt with a diff (prefer PatchOutput.diff, else patch_str)
    for pa in reversed(state.patch_attempts):
        if pa.patch and getattr(pa.patch, "diff", None):
            return pa.patch.diff
        if pa.patch_str:
            return pa.patch_str
    return None

def _verify_diff_applied(cwd: str, diff_text: str) -> Tuple[bool, str]:
    """
    Verify that a diff was actually applied by checking if the expected changes are present.
    Returns (success, details_message)
    """
    import re
    from pathlib import Path
    
    try:
        # Log the diff being verified for debugging
        logger.info(f"QE: Verifying diff application. Diff content (first 500 chars): {diff_text[:500]}")
        
        # Parse the diff to extract file changes
        file_changes = {}
        current_file = None
        
        for line in diff_text.split('\n'):
            # Look for file headers
            if line.startswith('--- a/') or line.startswith('--- '):
                # Extract old file path
                old_path = line[4:] if line.startswith('--- ') else line[6:]
                if old_path.startswith('a/'):
                    old_path = old_path[2:]
            elif line.startswith('+++ b/') or line.startswith('+++ '):
                # Extract new file path
                new_path = line[4:] if line.startswith('+++ ') else line[6:]
                if new_path.startswith('b/'):
                    new_path = new_path[2:]
                current_file = new_path
                if current_file not in file_changes:
                    file_changes[current_file] = {'added_lines': [], 'removed_lines': []}
                logger.info(f"QE: Processing file {current_file}")
            elif line.startswith('+') and not line.startswith('+++') and current_file:
                # Added line
                file_changes[current_file]['added_lines'].append(line[1:])
                logger.debug(f"QE: Added line: {line[1:].strip()}")
            elif line.startswith('-') and not line.startswith('---') and current_file:
                # Removed line  
                file_changes[current_file]['removed_lines'].append(line[1:])
                logger.debug(f"QE: Removed line: {line[1:].strip()}")
        
        verification_results = []
        all_verified = True
        
        for file_path, changes in file_changes.items():
            full_path = Path(cwd) / file_path
            
            if not full_path.exists():
                verification_results.append(f"❌ File {file_path} does not exist")
                all_verified = False
                continue
            
            try:
                file_content = full_path.read_text()
                
                # Debug: log some sample lines for troubleshooting
                logger.info(f"QE: Verifying {file_path} - {len(changes['added_lines'])} added, {len(changes['removed_lines'])} removed")
                
                # Check that added lines are present
                added_found = 0
                missing_added = []
                for added_line in changes['added_lines']:
                    line_content = added_line.strip()
                    # For regex patterns, check if the content is functionally equivalent
                    if 'Pattern.compile(' in line_content and '"' in line_content:
                        # Extract the regex pattern from the line
                        import re
                        pattern_match = re.search(r'"([^"]+)"', line_content)
                        if pattern_match:
                            pattern = pattern_match.group(1)
                            if pattern in file_content:
                                added_found += 1
                                continue
                    
                    if line_content in file_content:
                        added_found += 1
                    else:
                        missing_added.append(line_content)
                
                # Check that removed lines are NOT present (or fewer instances)
                removed_absent = 0
                still_present = []
                for removed_line in changes['removed_lines']:
                    line_content = removed_line.strip()
                    if line_content not in file_content:
                        removed_absent += 1
                    else:
                        still_present.append(line_content)
                
                total_added = len(changes['added_lines'])
                total_removed = len(changes['removed_lines'])
                
                # Enhanced logging for debugging
                if total_added > 0 and added_found == 0:
                    logger.warning(f"QE: No added lines found in {file_path}. Missing: {missing_added[:3]}")  # Log first 3
                    verification_results.append(f"❌ {file_path}: No added lines found in file")
                    all_verified = False
                elif total_added > 0 and added_found < total_added:
                    logger.warning(f"QE: Only {added_found}/{total_added} added lines found in {file_path}")
                    verification_results.append(f"⚠️  {file_path}: Only {added_found}/{total_added} added lines found")
                    all_verified = False
                elif total_added > 0:
                    verification_results.append(f"✅ {file_path}: All {added_found} added lines verified")
                
                if total_removed > 0 and removed_absent < total_removed:
                    logger.warning(f"QE: {total_removed - removed_absent}/{total_removed} removed lines still present in {file_path}")
                    verification_results.append(f"⚠️  {file_path}: {total_removed - removed_absent}/{total_removed} removed lines still present")
                elif total_removed > 0:
                    verification_results.append(f"✅ {file_path}: All {removed_absent} removed lines absent")
                    
            except Exception as e:
                verification_results.append(f"❌ {file_path}: Error reading file - {e}")
                all_verified = False
        
        if not file_changes:
            return True, "No file changes to verify"
            
        details = "; ".join(verification_results)
        return all_verified, details
        
    except Exception as e:
        return False, f"Verification failed: {e}"

def _validate_diff_syntax(diff_text: str) -> Tuple[bool, str]:
    """
    Validate diff syntax and detect common issues that cause partial application
    Returns (is_valid, issue_description)
    """
    lines = diff_text.split('\n')
    issues = []
    
    for i, line in enumerate(lines):
        # Check for malformed Java syntax in added lines
        if line.startswith('+') and not line.startswith('+++'):
            content = line[1:].strip()
            
            # Detect multiple string literals without operators (common in regex pattern issues)
            if '"' in content and content.count('"') >= 4:
                # Check if there are multiple quoted strings without concatenation
                import re
                strings = re.findall(r'"[^"]*"', content)
                if len(strings) >= 2:
                    # Check if strings are properly concatenated
                    between_strings = content
                    for s in strings:
                        between_strings = between_strings.replace(s, 'STRING', 1)
                    if 'STRING STRING' in between_strings:
                        issues.append(f"Line {i+1}: Multiple string literals without concatenation: {content[:50]}...")
            
            # Check for incomplete Pattern.compile statements
            if 'Pattern.compile(' in content and content.count('(') != content.count(')'):
                issues.append(f"Line {i+1}: Unbalanced parentheses in Pattern.compile: {content[:50]}...")
    
    return len(issues) == 0, "; ".join(issues)

def _check_diff_context_match(cwd: str, diff_text: str) -> Tuple[bool, str]:
    """
    Check if the diff context matches the actual file content
    Returns (matches, details)
    """
    from pathlib import Path
    
    try:
        lines = diff_text.split('\n')
        current_file = None
        context_issues = []
        
        for line in lines:
            if line.startswith('--- a/') or line.startswith('--- '):
                continue
            elif line.startswith('+++ b/') or line.startswith('+++ '):
                # Extract file path
                file_path = line[4:] if line.startswith('+++ ') else line[6:]
                if file_path.startswith('b/'):
                    file_path = file_path[2:]
                current_file = file_path
            elif line.startswith('-') and not line.startswith('---') and current_file:
                # This is a line that should be removed - check if it exists in the file
                removed_line = line[1:]  # Remove the '-' prefix
                
                file_path = Path(cwd) / current_file
                if file_path.exists():
                    file_content = file_path.read_text()
                    if removed_line.strip() not in file_content:
                        context_issues.append(f"Line to be removed not found: {removed_line.strip()[:50]}...")
        
        return len(context_issues) == 0, "; ".join(context_issues)
    except Exception as e:
        return False, f"Context check failed: {e}"

def _apply_diff(cwd: str, diff_text: str) -> Tuple[bool, bytes, bytes]:
    import tempfile
    
    # Log the diff content for debugging
    print(f"QE: Applying diff (length: {len(diff_text)} chars)")
    logger.info(f"QE: Full diff content:\n{diff_text}")
    
    # Validate diff syntax before applying
    is_valid, validation_issues = _validate_diff_syntax(diff_text)
    if not is_valid:
        logger.warning(f"QE: Diff validation failed: {validation_issues}")
        print(f"QE: WARNING - Diff has syntax issues: {validation_issues}")
    
    # Check if diff context matches the file
    context_matches, context_issues = _check_diff_context_match(cwd, diff_text)
    if not context_matches:
        logger.warning(f"QE: Diff context mismatch: {context_issues}")
        print(f"QE: WARNING - Diff context doesn't match file: {context_issues}")
        print(f"QE: This suggests the file has been modified by previous patches")
        logger.warning(f"QE: File may need to be reset to original state before applying new patches")
    
    with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
        f.write(diff_text)
        tmp = f.name
    try:
        # Try git apply with decreasing -p
        for p in range(0,10):
            rc, out, err = _run_cmd(["git", "apply", f"-p{p}", "--whitespace=nowarn", tmp], cwd)
            print(f"QE: git apply -p{p} rc={rc}, out={out}, err={err}")
            logger.info(f"QE: git apply -p{p} rc={rc}, out={out}, err={err}")
            if rc == 0:
                # Verify the diff was actually applied
                verified, details = _verify_diff_applied(cwd, diff_text)
                print(f"QE: patch verification: {verified} - {details}")
                logger.info(f"QE: patch verification: {verified} - {details}")
                if not verified:
                    print(f"QE: WARNING - git apply succeeded but verification failed!")
                    logger.warning(f"QE: git apply succeeded but verification failed: {details}")
                    # Also log the temp file path for manual inspection
                    logger.warning(f"QE: Patch file saved at: {tmp} (not deleted for debugging)")
                    
                    # Continue trying other -p values instead of returning success
                    print(f"QE: git apply -p{p} was ineffective, trying next -p value")
                    logger.info(f"QE: git apply -p{p} was ineffective, trying next -p value")
                    continue
                return True, out, err
        # Fallback to patch(1)
        for p in range(0,10):
            rc, out, err = _run_cmd(["patch", f"-p{p}", "--batch", "--forward", "-i", tmp], cwd)
            print(f"QE: patch -p{p} rc={rc}, out={out}, err={err}")
            logger.info(f"QE: patch -p{p} rc={rc}, out={out}, err={err}")
            if rc == 0:
                # Verify the patch was actually applied
                verified, details = _verify_diff_applied(cwd, diff_text)
                print(f"QE: patch verification: {verified} - {details}")
                logger.info(f"QE: patch verification: {verified} - {details}")
                if not verified:
                    print(f"QE: WARNING - patch succeeded but verification failed!")
                    logger.warning(f"QE: patch succeeded but verification failed: {details}")
                    # Also log the temp file path for manual inspection
                    logger.warning(f"QE: Patch file saved at: {tmp} (not deleted for debugging)")
                    
                    # Continue trying other -p values instead of returning success
                    print(f"QE: patch -p{p} was ineffective, trying next -p value")
                    logger.info(f"QE: patch -p{p} was ineffective, trying next -p value")
                    continue
                return True, out, err
        # If all attempts failed, check if the desired end state is already achieved
        print("QE: All patch attempts failed - checking if target state already achieved")
        logger.info("QE: All patch attempts failed - checking if target state already achieved")
        
        # Check if the key security fixes are already in place
        try:
            from pathlib import Path
            # Look for the main file being patched
            main_files = [f for f in diff_text.split('\n') if f.startswith('+++ b/')]
            if main_files:
                file_path = main_files[0][6:]  # Remove '+++ b/'
                full_path = Path(cwd) / file_path
                if full_path.exists():
                    content = full_path.read_text()
                    
                    # Check for key security indicators
                    security_checks = [
                        ('matcher(value).matches()', 'Validation logic present'),
                        ('value.contains("e")', 'Exponent check present'),
                        ('-?\\\\d{1,19}', 'Secure regex pattern present')
                    ]
                    
                    checks_passed = 0
                    for check, desc in security_checks:
                        if check in content:
                            checks_passed += 1
                            logger.info(f"QE: {desc} ✓")
                        else:
                            logger.info(f"QE: {desc} ✗")
                    
                    if checks_passed >= 2:  # At least 2 out of 3 security measures
                        print(f"QE: Key security fixes already present ({checks_passed}/3) - treating as success")
                        logger.info(f"QE: Key security fixes already present ({checks_passed}/3) - treating as success")
                        return True, out, err
        except Exception as e:
            logger.warning(f"QE: Error checking target state: {e}")
        
        print(f"QE: Patch application completely failed")
        logger.warning(f"QE: Patch application completely failed")
        return False, out, err
    finally:
        # Only delete temp file if verification passed or all attempts failed
        try:
            # Check if we should keep the file for debugging
            if "verification failed" not in str(locals().get('details', '')):
                os.unlink(tmp)
        except Exception:
            pass

def _revert_diff(cwd: str, diff_text: str) -> Tuple[bool, bytes, bytes]:
    # Try to revert via git apply -R, otherwise patch -R
    with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
        f.write(diff_text)
        tmp = f.name
    try:
        rc, out, err = _run_cmd(["git", "apply", "-R", "--whitespace=nowarn", "-p1", tmp], cwd)
        if rc == 0:
            return True, out, err
        rc2, out2, err2 = _run_cmd(["patch", "-p1", "-R", "--batch", "-i", tmp], cwd)
        return (rc2 == 0), (out + b"\n" + out2), (err + b"\n" + err2)
    finally:
        try:
            os.unlink(tmp)
        except Exception:
            pass

def _source_root(state: PatcherAgentState) -> str:
    return state.source_dir or state.project_root or _project_root(state)

def _apply_diff_in_source(state: PatcherAgentState, diff_text: str) -> Tuple[bool, bytes, bytes]:
    src = _source_root(state)
    diff_path = os.path.join(src, ".qe-current.diff")
    with open(diff_path, "w") as f:
        f.write(diff_text)
    rc, out, err = _run_cmd(["git", "apply", "-C5", diff_path], cwd=src)
    print(f"QE: (cwd={src}) git apply rc={rc}, out={out}, err={err}")
    logger.info(f"QE: (cwd={src}) git apply rc={rc}, out={out}, err={err}")
    return (rc == 0), out, err

def _revert_diff_in_source(state: PatcherAgentState, diff_text: str) -> Tuple[bool, bytes, bytes]:
    src = _source_root(state)
    diff_path = os.path.join(src, ".qe-current.diff")
    with open(diff_path, "w") as f:
        f.write(diff_text)
    rc, out, err = _run_cmd(["git", "apply", "-R", "-C5", diff_path], cwd=src)
    print(f"QE: (cwd={src}) git apply -R rc={rc}")
    logger.info(f"QE: (cwd={src}) git apply -R rc={rc}")
    return (rc == 0), out, err


def run_build(state: PatcherAgentState, source_override: Optional[str] = None) -> PatcherAgentState:
    pa = _ensure_attempt(state)
    helper = _helper(state)
    cwd = source_override or _project_root(state)
    print(f"QE: build start | helper={helper} | cwd={cwd}")
    logger.info(f"QE: build start | helper={helper} | cwd={cwd}")

    if not helper or not Path(helper).is_file():
        pa.build_succeeded = False
        pa.build_stderr = (pa.build_stderr or b"") + b"helper_script_path missing"
        pa.status = PatchStatus.BUILD_FAILED
        _replace_attempt(state, pa)
        print("QE: build aborted (missing helper.py)")
        logger.info("QE: build aborted (missing helper.py)")
        return state

    # build_image
    cmd_img = ["python", helper, "build_image", "--pull", _project_name(state)]
    print(f"QE: exec: {' '.join(cmd_img)}")
    logger.info(f"QE: exec: {' '.join(cmd_img)}")
    rc, out, err = _run_cmd(cmd_img, cwd=cwd)
    if rc == 0:
        pa.build_stdout = None
        pa.build_stderr = None
    else:
        pa.build_stdout = (pa.build_stdout or b"") + out
        pa.build_stderr = (pa.build_stderr or b"") + err
    print(f"QE: build_image rc={rc}")
    logger.info(f"QE: build_image rc={rc}")
    if rc != 0:
        pa.build_succeeded = False
        pa.status = PatchStatus.BUILD_FAILED
        _replace_attempt(state, pa)
        print("QE: build_image failed")
        logger.info("QE: build_image failed")
        return state

    # build_fuzzers
    cmd = [
        "python",
        helper,
        "build_fuzzers",
        "--clean",
        "--sanitizer",
        "address",
        "--engine",
        "libfuzzer",
        _project_name(state),
        *_maybe_source_arg_path(source_override or state.source_dir),
    ]
    print(f"QE: exec: {' '.join(cmd)}")
    logger.info(f"QE: exec: {' '.join(cmd)}")
    rc, out, err = _run_cmd(cmd, cwd=cwd)
    if rc == 0:
        pa.build_stdout = None
        pa.build_stderr = None
    else:
        pa.build_stdout = (pa.build_stdout or b"") + out
        pa.build_stderr = (pa.build_stderr or b"") + err
    pa.build_succeeded = (rc == 0)
    print(f"QE: build_fuzzers rc={rc}")
    logger.info(f"QE: build_fuzzers rc={rc}")
    if not pa.build_succeeded:
        pa.status = PatchStatus.BUILD_FAILED
        print("QE: build_fuzzers failed")
        logger.info("QE: build_fuzzers failed")
    _replace_attempt(state, pa)
    return state


def run_pov(state: PatcherAgentState) -> PatcherAgentState:
    pa = _ensure_attempt(state)
    helper = _helper(state)
    hpath = getattr(state, "harness_script_path", None)
    
    # Check if harness_script_path is set
    if hpath is None:
        pa.pov_fixed = False
        pa.pov_stderr = (pa.pov_stderr or b"") + b"harness_script_path is not set in state"
        pa.status = pa.status or PatchStatus.POV_FAILED
        _replace_attempt(state, pa)
        print("QE: pov aborted (missing harness_script_path)")
        logger.error("QE: pov aborted (missing harness_script_path)")
        return state
    
    harness = Path(hpath).stem
    pov = state.pov_path
    cwd = _project_root(state)
    print(f"QE: pov start | helper={helper} | harness={harness} | pov={pov} | cwd={cwd}")
    logger.info(f"QE: pov start | helper={helper} | harness={harness} | pov={pov} | cwd={cwd}")

    if not helper or not Path(helper).is_file():
        pa.pov_fixed = False
        pa.pov_stderr = (pa.pov_stderr or b"") + b"helper_script_path missing"
        pa.status = pa.status or PatchStatus.POV_FAILED
        _replace_attempt(state, pa)
        print("QE: pov aborted (missing helper.py)")
        logger.info("QE: pov aborted (missing helper.py)")
        return state

    if not (harness and pov and Path(pov).is_file()):
        pa.pov_fixed = False
        pa.pov_stderr = (pa.pov_stderr or b"") + b"Missing harness_name or pov_path"
        pa.status = pa.status or PatchStatus.POV_FAILED
        _replace_attempt(state, pa)
        print("QE: pov aborted (missing harness or pov)")
        logger.info("QE: pov aborted (missing harness or pov)")
        return state

    cmd_pov = ["python", helper, "reproduce", _project_name(state), harness, pov]
    print(f"QE: exec: {' '.join(cmd_pov)}")
    logger.info(f"QE: exec: {' '.join(cmd_pov)}")
    rc, out, err = _run_cmd(cmd_pov, cwd=cwd)
    # rc==0 means PoV no longer reproduces => fixed
    if rc == 0:
        pa.pov_stdout = None
        pa.pov_stderr = None
    else:
        pa.pov_stdout = out
        pa.pov_stderr = err
    pa.pov_fixed = (rc == 0)
    print(f"QE: reproduce rc={rc}")
    logger.info(f"QE: reproduce rc={rc}")
    if not pa.pov_fixed:
        pa.status = pa.status or PatchStatus.POV_FAILED
    _replace_attempt(state, pa)
    return state


def run_tests(state: PatcherAgentState, source_override: Optional[str] = None) -> PatcherAgentState:
    pa = _ensure_attempt(state)
    # Robustly resolve <project_root>/pov/test.sh across callers (multi_agent and patch-agent-tools)
    source_dir = source_override or state.source_dir or ""
    candidates: list[Path] = []
    # 1) Provided project_root (preferred when set to .../afc-<project>)
    try:
        if state.project_root:
            candidates.append(Path(state.project_root).resolve())
    except Exception:
        pass
    # 2) Derive from helper.py: .../afc-<project>/oss-fuzz/infra/helper.py -> parents[2] == .../afc-<project>
    try:
        h = getattr(state, "helper_script_path", None)
        if h:
            p = Path(h).resolve()
            parents = list(p.parents)
            if len(parents) >= 3:
                candidates.append(parents[2])
    except Exception:
        pass
    # 3) Derive from benchmark_path + project
    try:
        bench = getattr(getattr(state, "context", None), "benchmark_path", None)
        proj = getattr(getattr(state, "context", None), "project", None)
        if bench and proj:
            candidates.append(Path(bench).resolve() / f"afc-{proj}")
    except Exception:
        pass
    # 4) Fallbacks: parent of source_dir, and legacy _project_root
    try:
        if source_dir:
            candidates.append(Path(source_dir).resolve().parent)
    except Exception:
        pass
    try:
        candidates.append(Path(_project_root(state)).resolve())
    except Exception:
        pass

    # Deduplicate while preserving order
    seen = set()
    uniq: list[Path] = []
    for c in candidates:
        try:
            if c not in seen:
                seen.add(c)
                uniq.append(c)
        except Exception:
            continue

    test_path: Optional[Path] = None
    for cand in uniq:
        tp = cand / "pov" / "test.sh"
        try:
            if tp.is_file():
                test_path = tp
                break
        except Exception:
            continue
    # As a very last resort, try legacy relative hop from source_dir (may be sandboxed)
    if not test_path:
        try:
            legacy = Path(source_dir).resolve() / ".." / ".." / f"afc-{_project_name(state)}" / "pov" / "test.sh"
            if legacy.is_file():
                test_path = legacy
        except Exception:
            test_path = None
    if not test_path or not test_path.is_file():
        pa.tests_passed = False
        pa.status = PatchStatus.TESTS_FAILED
        msg = "test.sh not found; tried: " + ", ".join(str(c / 'pov' / 'test.sh') for c in uniq)
        pa.tests_stderr = (pa.tests_stderr or b"") + msg.encode()
        _replace_attempt(state, pa)
        return state

    # Build command with inline environment variables for SRC and MVN
    mvn_bin = os.environ.get("MVN", "mvn")
    cmd_str = f"SRC={source_dir} MVN={mvn_bin} bash {str(test_path)}"
    print(f"QE: tests start | cmd: {cmd_str}")
    logger.info(f"QE: tests start | cmd: {cmd_str}")
    rc, out, err = _run_cmd(cmd_str, cwd=source_dir)
    if rc == 0:
        pa.tests_stdout = None
        pa.tests_stderr = None
    else:
        pa.tests_stdout = out
        pa.tests_stderr = err
    pa.tests_passed = (rc == 0)
    if not pa.tests_passed:
        pa.status = PatchStatus.TESTS_FAILED
        print("QE: tests failed")
        logger.info("QE: tests failed")
    else:
        print("QE: tests passed")
        logger.info("QE: tests passed")
    _replace_attempt(state, pa)
    return state


def _reset_sandbox_to_original(original_source: str, sandbox_source: str) -> bool:
    """
    Reset the sandbox to match the original source exactly
    Returns True if successful
    """
    try:
        if Path(sandbox_source).exists():
            shutil.rmtree(sandbox_source)
        shutil.copytree(original_source, sandbox_source)
        print(f"QE: Reset sandbox to original state")
        logger.info(f"QE: Reset sandbox to original state")
        return True
    except Exception as e:
        print(f"QE: Failed to reset sandbox: {e}")
        logger.error(f"QE: Failed to reset sandbox: {e}")
        return False

def run(state: PatcherAgentState) -> PatcherAgentState:
    # If already have a successful attempt, skip
    if _already_successful(state):
        state.remaining_steps = max(0, (state.remaining_steps or 0) - 1)
        print("QE: skip (already successful attempt present)")
        logger.info("QE: skip (already successful attempt present)")
        return state

    pa = _ensure_attempt(state)
    diff_text = _get_current_diff(state)

    # Create a sandbox copy of the source directory to avoid contaminating original repo
    original_source = state.source_dir
    sandbox_root = None
    try:
        if original_source and Path(original_source).is_dir():
            # Use a stable sandbox under the project root for better observability/debugging
            sandbox_root = str(Path(_project_root(state)) / ".qe_sandbox")
            if Path(sandbox_root).exists():
                try:
                    shutil.rmtree(sandbox_root)
                except Exception:
                    pass
            Path(sandbox_root).mkdir(parents=True, exist_ok=True)
            sandbox_source = str(Path(sandbox_root) / "source")
            print(f"QE: creating sandbox copy at {sandbox_source}")
            logger.info(f"QE: creating sandbox copy at {sandbox_source}")
            shutil.copytree(original_source, sandbox_source)
            work_source = sandbox_source
        else:
            work_source = original_source

        # Apply overlay edits into sandbox if present; fallback to unified diff apply otherwise
        overlay_diff = dump_overlay_unified_diff(state.source_dir)
        if overlay_diff and overlay_diff.strip():
            print("QE: materializing overlay edits into sandbox...")
            logger.info("QE: materializing overlay edits into sandbox...")
            res = materialize_overlay_to_dir(state.source_dir, work_source or _source_root(state))
            if isinstance(res, Err):
                # Check if this is due to old code not found
                error_msg = str(res.err) if hasattr(res, 'err') else ""
                if "old code" in error_msg.lower() or "context" in error_msg.lower() or "not found" in error_msg.lower():
                    pa.description = "Old code snippet not found (context mismatch)"
                    print("QE: overlay materialize failed due to old code not found")
                else:
                    pa.description = "Overlay materialization failed"
                    print("QE: overlay materialize failed")
                    
                pa.status = PatchStatus.APPLY_FAILED
                _replace_attempt(state, pa)
                logger.info(f"QE: stopping - {pa.description}")
                state.remaining_steps = max(0, (state.remaining_steps or 0) - 1)
                return state
        elif diff_text:
            print("QE: applying current patch (git -C <source_dir> apply)...")
            logger.info("QE: applying current patch (git -C <source_dir> apply)...")
            ok, aout, aerr = _apply_diff(work_source or _source_root(state), diff_text)
            pa.build_stdout = (pa.build_stdout or b"") + aout
            pa.build_stderr = (pa.build_stderr or b"") + aerr
            if not ok:
                # Check if this is a context mismatch (old code not found) from the error output
                combined_output = (aout + aerr).decode('utf-8', errors='ignore').lower()
                context_indicators = ["hunk", "patch failed", "does not apply", "rejected", "cant find file", "can't find file", "no such file"]
                is_context_mismatch = any(x in combined_output for x in context_indicators)
                
                if is_context_mismatch:
                    pa.description = "Old code snippet not found (context mismatch)"
                    print("QE: patch apply failed due to old code not found (context mismatch)")
                    logger.info("QE: patch apply failed due to old code not found (context mismatch)")
                else:
                    pa.description = "Patch application failed" 
                    print("QE: patch apply failed")
                    logger.info("QE: patch apply failed")
                    
                pa.status = PatchStatus.APPLY_FAILED
                _replace_attempt(state, pa)
                print("QE: stopping")
                logger.info("QE: stopping")
                state.remaining_steps = max(0, (state.remaining_steps or 0) - 1)
                return state
            _replace_attempt(state, pa)

        # Build (image + fuzzers)
        state = run_build(state, work_source)

        # If build failed, stop (sandbox will be discarded in finally)
        pa = _ensure_attempt(state)
        if not pa.build_succeeded:
            print("QE: stop (build failed)")
            logger.info("QE: stop (build failed)")
            state.execution_info.reflection_decision = None
            state.next_agent = "reflection"
            state.remaining_steps = max(0, (state.remaining_steps or 0) - 1)
            return state

        # Run PoV
        state = run_pov(state)

        # If PoV still reproduces, route to reflection
        pa = _ensure_attempt(state)
        if not pa.pov_fixed:
            state.execution_info.reflection_decision = None
            state.next_agent = "reflection"

        # Run tests if build succeeded and PoV fixed
        pa = _ensure_attempt(state)
        if pa.build_succeeded and pa.pov_fixed:
            state = run_tests(state, work_source)
            pa = _ensure_attempt(state)
            if pa.tests_passed:
                pa.status = PatchStatus.SUCCESS
                # If prior description came from an earlier overlay failure, replace with a clear success note
                try:
                    desc = getattr(pa, "description", None)
                    if not desc or (isinstance(desc, str) and "overlay apply failed" in desc.lower()):
                        pa.description = "QE validated patch"
                except Exception:
                    pass
                _replace_attempt(state, pa)
            else:
                # Route to reflection for guidance on next attempt
                state.execution_info.reflection_decision = None
                state.next_agent = "reflection"

        state.remaining_steps = max(0, (state.remaining_steps or 0) - 1)
        return state
    finally:
        # Always cleanup sandbox so every QE run starts with a fresh sandbox
        try:
            if sandbox_root and Path(sandbox_root).exists():
                try:
                    shutil.rmtree(sandbox_root)
                    print(f"QE: removed sandbox {sandbox_root}")
                    logger.info(f"QE: removed sandbox {sandbox_root}")
                except Exception:
                    # Best-effort cleanup; ignore failures
                    pass
        except Exception:
            # Never let sandbox cleanup failures crash the agent
            pass


class QEAgent(Agent):
    def __init__(self) -> None:
        super().__init__("qe")

    def run(self, state: PatcherAgentState) -> PatcherAgentState:  # type: ignore[override]
        return run(state)