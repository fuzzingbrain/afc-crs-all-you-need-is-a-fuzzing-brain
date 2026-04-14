"""Fuzzer source-file discovery.

Given a fuzzer binary produced by an OSS-Fuzz build, figure out which
source file that binary was compiled from. The logic combines four
strategies, tried in order:

1. A direct tree-walk of ``project_src_dir`` for files that define
   ``LLVMFuzzerTestOneInput`` (the libFuzzer entry point).
2. Parsing ``Makefile`` / ``build.sh`` / ``CMakeLists.txt`` contents that
   mention the fuzzer target to extract a source path.
3. An optional LLM-based identifier that is handed the build scripts
   plus the collected candidate source files.
4. A purely name-based fallback (``fuzzer_name.c``, ``base_name.cc``, ...).

Plus a small public helper, :func:`is_likely_source_for_fuzzer`, used
both here and by legacy code for naming heuristics.
"""
from __future__ import annotations

import logging
import os
import re
import tarfile
from typing import Dict, List, Optional, TYPE_CHECKING

from common.code.cleanup import strip_license_text

if TYPE_CHECKING:
    from common.llm.client import LLMClient

logger = logging.getLogger(__name__)

_MAX_SOURCE_FILE_BYTES = 50_000
_MAX_SOURCE_FILES_BEFORE_FILTER = 20
_LLVM_MARKER = "LLVMFuzzerTestOneInput"


# ---------------------------------------------------------------------------
# Public naming heuristic
# ---------------------------------------------------------------------------


def is_likely_source_for_fuzzer(file_base: str, fuzzer_name: str, base_name: str) -> bool:
    """Return True when ``file_base`` plausibly names the source for ``fuzzer_name``.

    ``file_base`` is the source file's basename without extension,
    ``fuzzer_name`` is the fuzzer binary name, and ``base_name`` is a
    pre-stripped variant (typically ``fuzzer_name`` with the trailing
    ``_fuzzer`` removed). Checks a number of conventional mappings used
    throughout OSS-Fuzz projects.
    """
    if file_base == fuzzer_name or file_base == base_name:
        return True
    if fuzzer_name == f"{file_base}_fuzzer":
        return True
    if base_name == f"{file_base}_fuzz":
        return True
    if base_name == f"fuzz_{file_base}":
        return True
    if base_name == f"{file_base}_test":
        return True
    if base_name == f"test_{file_base}":
        return True
    if fuzzer_name.startswith(f"{file_base}_"):
        return True
    if base_name == file_base.replace("lib", ""):
        return True
    if file_base == base_name.replace("lib", ""):
        return True
    return False


# ---------------------------------------------------------------------------
# Source extensions
# ---------------------------------------------------------------------------


def _source_extensions(language: str) -> List[str]:
    """Return candidate source extensions for ``language``."""
    if not language.startswith("c"):
        return [".java"]
    return [".c", ".cc", ".cpp"]


# ---------------------------------------------------------------------------
# Phase 1: direct LLVMFuzzerTestOneInput scan
# ---------------------------------------------------------------------------


def _find_by_llvm_marker(project_src_dir: str, extensions: List[str]) -> Optional[str]:
    """Return the content of the first source file defining ``LLVMFuzzerTestOneInput``."""
    for root, _, files in os.walk(project_src_dir):
        for name in files:
            if not any(name.endswith(ext) for ext in extensions):
                continue
            path = os.path.join(root, name)
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                    content = fh.read()
            except OSError as exc:
                logger.debug("Error reading %s: %s", path, exc)
                continue
            if _LLVM_MARKER in content:
                logger.debug("Found %s in %s", _LLVM_MARKER, path)
                return content
    return None


# ---------------------------------------------------------------------------
# Phase 2: build-script parsing
# ---------------------------------------------------------------------------


def _read_file(path: str) -> Optional[str]:
    """Read a text file, returning ``None`` on I/O error."""
    try:
        with open(path, "r") as fh:
            return fh.read()
    except OSError as exc:
        logger.debug("Error reading %s: %s", path, exc)
        return None


def _collect_build_scripts(
    project_dir: str,
    project_src_dir: str,
    focus: str,
    project_name: str,
    fuzzer_name: str,
) -> Dict[str, str]:
    """Gather relevant build scripts that mention ``fuzzer_name``.

    Searches, in order:
        * ``{project_dir}/fuzz-tooling/projects/{project_name}`` for ``build.sh``
        * ``project_src_dir`` for ``Makefile`` / ``CMakeLists.txt`` (depth <= 3)
        * ``{project_dir}/{focus}`` for ``build.sh`` (only when nothing found yet)
    """
    scripts: Dict[str, str] = {}

    project_path = os.path.join(project_dir, f"fuzz-tooling/projects/{project_name}")
    if os.path.exists(project_path):
        for root, _, files in os.walk(project_path):
            if "build.sh" in files:
                path = os.path.join(root, "build.sh")
                content = _read_file(path)
                if content is not None:
                    scripts[path] = content

    if os.path.exists(project_src_dir):
        for root, _, files in os.walk(project_src_dir):
            depth = root[len(project_src_dir):].count(os.sep)
            if depth > 3:
                continue
            for filename in files:
                if filename not in ("Makefile", "makefile", "GNUmakefile", "CMakeLists.txt"):
                    continue
                path = os.path.join(root, filename)
                content = _read_file(path)
                if content is None:
                    continue
                if fuzzer_name in content or "fuzzer" in content.lower():
                    scripts[path] = content
                    logger.debug("Found relevant build script: %s", path)

    if not scripts:
        focus_path = os.path.join(project_dir, focus)
        if os.path.exists(focus_path):
            for root, _, files in os.walk(focus_path):
                if "build.sh" in files:
                    path = os.path.join(root, "build.sh")
                    content = _read_file(path)
                    if content is not None:
                        scripts[path] = content

    return scripts


_MAKEFILE_NAMES = ("Makefile", "makefile", "GNUmakefile")


def _parse_makefile_for_source(content: str, fuzzer_name: str) -> Optional[str]:
    """Extract a source path referenced next to ``fuzzer_name`` in a Makefile."""
    pattern1 = rf"{re.escape(fuzzer_name)}[^:]*:\s*\\?\s*([^\s]+\.(?:c|cc|cpp))"
    for match in re.finditer(pattern1, content, re.MULTILINE | re.DOTALL):
        logger.debug("Makefile pattern 1 matched: %s", match.group(1))
        return match.group(1)

    lines = content.split("\n")
    for i, line in enumerate(lines):
        if fuzzer_name in line and ":" in line:
            for j in range(i + 1, min(i + 5, len(lines))):
                next_line = lines[j].strip()
                if next_line and not next_line.startswith("#"):
                    source_match = re.search(r"([^\s]+\.(?:c|cc|cpp))\s*$", next_line)
                    if source_match:
                        logger.debug("Makefile multi-line match: %s", source_match.group(1))
                        return source_match.group(1)
                if ":" in next_line and not next_line.startswith("\t"):
                    break

    pattern2 = rf"-D[A-Z_]*FUZZ[A-Z_]*.*?-o.*?{re.escape(fuzzer_name)}[^\s]*\s+([^\s]+\.(?:c|cc|cpp))"
    for match in re.finditer(pattern2, content, re.DOTALL):
        candidate = match.group(1)
        if "$" in candidate:
            continue
        logger.debug("Makefile -D flag match: %s", candidate)
        return candidate

    for line in content.split("\n"):
        if fuzzer_name in line and any(ext in line for ext in (".c", ".cc", ".cpp")):
            parts = re.findall(r"([^\s]+\.(?:c|cc|cpp))", line)
            for part in parts:
                if "$" not in part and part not in ("$NJS_CC", "$CC", "$CXX"):
                    logger.debug("Makefile line-scan match: %s", part)
                    return part

    return None


def _parse_buildsh_for_source(content: str, fuzzer_name: str) -> Optional[str]:
    """Extract a source path compiled next to ``fuzzer_name`` in a build.sh."""
    pattern1 = rf"\$(?:CXX|CC).*?-o.*?{re.escape(fuzzer_name)}[^\s]*\s+([^\s]+\.(?:c|cc|cpp))"
    for match in re.finditer(pattern1, content):
        candidate = match.group(1)
        if "$" not in candidate:
            logger.debug("build.sh -o match: %s", candidate)
            return candidate

    pattern2 = rf"compile_(?:fuzzer|libfuzzer)[^\n]+([^\s]+\.(?:c|cc|cpp))[^\n]+{re.escape(fuzzer_name)}"
    for match in re.finditer(pattern2, content):
        logger.debug("build.sh compile_fuzzer (src first) match: %s", match.group(1))
        return match.group(1)

    pattern3 = rf"compile_(?:fuzzer|libfuzzer)[^\n]+{re.escape(fuzzer_name)}[^\n]+([^\s]+\.(?:c|cc|cpp))"
    for match in re.finditer(pattern3, content):
        logger.debug("build.sh compile_fuzzer (name first) match: %s", match.group(1))
        return match.group(1)

    return None


def _parse_cmake_for_source(content: str, fuzzer_name: str) -> Optional[str]:
    """Extract a source path next to ``add_executable(fuzzer_name ...)`` in CMakeLists."""
    pattern = rf"add_executable\s*\(\s*{re.escape(fuzzer_name)}\s+([^\s)]+\.(?:c|cc|cpp))"
    for match in re.finditer(pattern, content):
        logger.debug("CMake add_executable match: %s", match.group(1))
        return match.group(1)
    return None


def _parse_build_scripts(build_scripts: Dict[str, str], fuzzer_name: str) -> Optional[str]:
    """Iterate build scripts, dispatching per script kind."""
    for path, content in build_scripts.items():
        name = os.path.basename(path)

        if name in _MAKEFILE_NAMES or "make" in path.lower():
            result = _parse_makefile_for_source(content, fuzzer_name)
            if result:
                return result
            continue

        if name == "build.sh" or name.endswith(".sh"):
            result = _parse_buildsh_for_source(content, fuzzer_name)
            if result:
                return result
            continue

        if name == "CMakeLists.txt":
            result = _parse_cmake_for_source(content, fuzzer_name)
            if result:
                return result

    return None


# ---------------------------------------------------------------------------
# Phase 3: gather candidate source files
# ---------------------------------------------------------------------------


def _dirs_referenced_in_build_scripts(build_scripts: Dict[str, str]) -> List[str]:
    """Extract directory fragments referenced inside build script contents."""
    seen: List[str] = []
    for content in build_scripts.values():
        patterns = re.findall(r"(?:^|\s)([\w_]+/[\w_/]+\.(?:c|cc|cpp))", content, re.MULTILINE)
        for p in patterns:
            dir_path = os.path.dirname(p)
            if dir_path and dir_path not in seen:
                seen.append(dir_path)
    return seen


def _unpack_fuzzer_archives(project_path: str) -> List[str]:
    """Return any fuzzer-named directories found (or extracted) under ``project_path/pkgs``."""
    fuzz_dirs: List[str] = []
    pkgs_dir = os.path.join(project_path, "pkgs")
    if not os.path.isdir(pkgs_dir):
        return fuzz_dirs

    for entry in os.listdir(pkgs_dir):
        abs_entry = os.path.join(pkgs_dir, entry)
        if os.path.isdir(abs_entry) and "fuzzer" in entry.lower():
            fuzz_dirs.append(abs_entry)
            logger.debug("Found extracted pkg dir: %s", abs_entry)

    for entry in os.listdir(pkgs_dir):
        if not entry.endswith((".tar.gz", ".tgz")) or "fuzzer" not in entry.lower():
            continue
        archive_path = os.path.join(pkgs_dir, entry)
        try:
            with tarfile.open(archive_path, "r:gz") as tar:
                top_dirs = {m.name.split("/")[0] for m in tar.getmembers()}
                tar.extractall(path=pkgs_dir)  # noqa: S202 — trusted workspace
            for td in top_dirs:
                extracted = os.path.join(pkgs_dir, td)
                if os.path.isdir(extracted):
                    fuzz_dirs.append(extracted)
                    logger.debug("Extracted %s into %s", archive_path, extracted)
                elif pkgs_dir not in fuzz_dirs:
                    fuzz_dirs.append(pkgs_dir)
        except (tarfile.TarError, OSError) as exc:
            logger.warning("Error extracting %s: %s", archive_path, exc)

    return fuzz_dirs


def _enumerate_fuzz_dirs(
    project_dir: str,
    project_src_dir: str,
    focus: str,
    build_scripts: Dict[str, str],
    project_path: str,
) -> List[str]:
    """Discover directories likely to contain fuzzer sources.

    The search is a union of several heuristics: extracted ``pkgs/*.tar.gz``
    archives, ``fuzz/`` sibling directories beside build scripts, any
    ``*fuzz*`` directories under ``focus_path``, and as a last resort a
    broad walk of ``project_src_dir`` looking for fuzzer-ish names or
    fuzzer-ish file contents.
    """
    fuzz_dirs: List[str] = []
    fuzz_dirs.extend(_unpack_fuzzer_archives(project_path))

    for script_path in build_scripts:
        fuzz_dir = os.path.join(os.path.dirname(script_path), "fuzz")
        if os.path.exists(fuzz_dir):
            fuzz_dirs.append(fuzz_dir)

    focus_path = os.path.join(project_dir, focus)
    if os.path.exists(focus_path):
        for root, dirs, _ in os.walk(focus_path):
            if root.count(os.sep) - focus_path.count(os.sep) > 5:
                continue
            for dir_name in dirs:
                if "fuzz" in dir_name.lower() and "CMakeFiles" not in root:
                    fuzz_dir = os.path.join(root, dir_name)
                    if fuzz_dir not in fuzz_dirs:
                        fuzz_dirs.append(fuzz_dir)
                        logger.debug("Found fuzzer directory: %s", fuzz_dir)

    if not fuzz_dirs:
        extra: List[str] = []
        for root, dirs, files in os.walk(project_src_dir):
            if root.count(os.sep) - project_src_dir.count(os.sep) > 7:
                continue
            for dir_name in dirs:
                lower = dir_name.lower()
                if "fuzz" in lower or "test" in lower or "harness" in lower:
                    extra.append(os.path.join(root, dir_name))
            if any("fuzz" in f.lower() or "_test" in f.lower() or "test_" in f.lower() for f in files):
                extra.append(root)
        for dp in extra:
            if dp not in fuzz_dirs:
                fuzz_dirs.append(dp)

    logger.debug("Discovered %d fuzz-related directories", len(fuzz_dirs))
    return fuzz_dirs


def _collect_candidate_sources(
    fuzz_dirs: List[str],
    extensions: List[str],
    fuzzer_name: str,
    base_name: str,
) -> tuple[Optional[str], Dict[str, str]]:
    """Walk the given fuzz dirs, collecting candidate sources.

    Returns ``(early_match_content, remaining_candidates)``. If a file is
    found whose basename matches the fuzzer via
    :func:`is_likely_source_for_fuzzer`, it is returned as
    ``early_match_content`` and iteration stops. Otherwise every readable
    file under the 50 KB limit becomes a candidate.
    """
    candidates: Dict[str, str] = {}
    for fuzz_dir in fuzz_dirs:
        for root, _, files in os.walk(fuzz_dir):
            for name in files:
                if not any(name.endswith(ext) for ext in extensions):
                    continue
                path = os.path.join(root, name)
                file_base = os.path.splitext(name)[0]

                if is_likely_source_for_fuzzer(file_base, fuzzer_name, base_name):
                    content = _read_file(path)
                    if content is not None:
                        logger.debug("Early name match: %s", path)
                        return content, candidates

                content = _read_file(path)
                if content is not None and len(content) < _MAX_SOURCE_FILE_BYTES:
                    candidates[path] = content

    return None, candidates


def _filter_candidates(
    source_files: Dict[str, str],
    fuzzer_name: str,
    base_name: str,
) -> Dict[str, str]:
    """Prune the candidate pool when it grew too large."""
    if len(source_files) <= _MAX_SOURCE_FILES_BEFORE_FILTER:
        return source_files

    filtered: Dict[str, str] = {}
    for path, content in source_files.items():
        name = os.path.basename(path)
        if fuzzer_name in name or base_name in name:
            filtered[path] = content

    if len(filtered) < 5:
        for path, content in source_files.items():
            if path in filtered:
                continue
            if fuzzer_name in content or base_name in content:
                filtered[path] = content
                if len(filtered) >= 10:
                    break

    logger.debug("Filtered candidate pool to %d files", len(filtered))
    return filtered


# ---------------------------------------------------------------------------
# Phase 4: LLM identification
# ---------------------------------------------------------------------------


def _build_llm_prompt(
    build_scripts: Dict[str, str],
    files_to_analyze: Dict[str, str],
    fuzzer_name: str,
    base_name: str,
    fuzzer_path: str,
) -> str:
    """Build the prompt used to ask an LLM which candidate file is the fuzzer source."""
    preamble = (
        f"I need to identify the source code file for a fuzzer named "
        f"'{fuzzer_name}' (base name: '{base_name}').\n"
        f"Please analyze the following build scripts and source files to "
        f"determine which file is most likely the fuzzer source.\n\n"
        f"The fuzzer binary is located at: {fuzzer_path}\n\n"
        f"BUILD SCRIPTS:\n"
    )

    parts = [preamble]
    for path, content in build_scripts.items():
        truncated = content[:5000] + ("\n... (truncated)" if len(content) > 5000 else "")
        parts.append(f"\n--- {path} ---\n{truncated}\n")

    parts.append("\nSOURCE FILES:\n")
    for path, content in files_to_analyze.items():
        lines = content.split("\n")
        if _LLVM_MARKER in content:
            marker_idx: Optional[int] = next(
                (i for i, line in enumerate(lines) if _LLVM_MARKER in line), None
            )
            if marker_idx is not None:
                start = max(0, marker_idx - 10)
                end = min(len(lines), marker_idx + 30)
                preview = "\n".join(lines[start:end])
            else:
                preview = "\n".join(lines[:50])
                if len(lines) > 50:
                    preview += "\n... (file continues)"
        else:
            preview = "\n".join(lines[:50])
            if len(lines) > 50:
                preview += "\n... (file continues)"
        parts.append(f"\n--- {path} ---\n{preview}\n")

    parts.append(
        "\nBased on the build scripts and source files above, which file "
        "is the source code for the fuzzer?\nLook for:\n"
        f"1. Files containing {_LLVM_MARKER} function\n"
        "2. Files referenced in build scripts for compiling the fuzzer\n"
        "3. Files with fuzzer-related compilation flags (like -DFUZZER_TARGET)\n\n"
        "IMPORTANT: Return the SOURCE FILE path, NOT the build artifact path.\n"
        "- Good: external/njs_shell.c, src/fuzzer.cc, fuzz/test_fuzzer.c\n"
        f"- Bad: /build/{fuzzer_name}, /out/{fuzzer_name}, build/{fuzzer_name}\n\n"
        f"The fuzzer BINARY is at: {fuzzer_path}\n"
        "You need to find the SOURCE FILE that was compiled to create this binary.\n\n"
        "Please respond with ONLY the source file path "
        "(e.g., external/shell.c or src/fuzzer.cc), nothing else.\n"
    )

    return "".join(parts)


def _extract_path_from_llm_response(response: str, fuzzer_name: str) -> Optional[str]:
    """Parse an LLM identifier response into a plausible source path."""
    match = re.search(r"(/[^\s]+\.(?:c|cc|cpp|java))", response) or re.search(
        r"([^\s]+\.(?:c|cc|cpp|java))", response
    )
    if not match:
        return None

    path = match.group(1)
    artifact_markers = ("/build/", "/out/", "build/" + fuzzer_name, "out/" + fuzzer_name)
    if any(marker in path for marker in artifact_markers):
        logger.warning("LLM returned a build-artifact path, rejecting: %s", path)
        return None

    return path


def _resolve_llm_identified_path(
    identified_path: str,
    source_files: Dict[str, str],
    project_src_dir: str,
) -> Optional[str]:
    """Try several path resolutions for an LLM-identified source file name."""
    identified_basename = os.path.basename(identified_path)
    for path, content in source_files.items():
        if os.path.basename(path) == identified_basename:
            logger.debug("Matched LLM path to collected source: %s", path)
            return content

    if identified_path in source_files:
        return source_files[identified_path]

    if os.path.exists(identified_path):
        content = _read_file(identified_path)
        if content is not None:
            return content

    relative_path = os.path.join(project_src_dir, identified_path)
    if os.path.exists(relative_path):
        content = _read_file(relative_path)
        if content is not None:
            return content

    return None


def _identify_via_llm(
    build_scripts: Dict[str, str],
    source_files: Dict[str, str],
    llvm_marker_files: Dict[str, str],
    fuzzer_name: str,
    base_name: str,
    fuzzer_path: str,
    project_src_dir: str,
    llm_client: "LLMClient",
) -> Optional[str]:
    """Run the LLM identification pass. Returns the source content on success."""
    files_to_analyze = llvm_marker_files if len(llvm_marker_files) > 1 else source_files

    prompt = _build_llm_prompt(
        build_scripts, files_to_analyze, fuzzer_name, base_name, fuzzer_path
    )
    response, success = llm_client.call(
        [{"role": "user", "content": prompt}], "gemini-2.5-flash"
    )
    if not success:
        return None

    identified = _extract_path_from_llm_response(response.strip(), fuzzer_name)
    if not identified:
        return None

    logger.debug("LLM identified fuzzer source as: %s", identified)
    return _resolve_llm_identified_path(identified, source_files, project_src_dir)


# ---------------------------------------------------------------------------
# Phase 5: name-based fallback
# ---------------------------------------------------------------------------


def _fallback_by_name(
    source_files: Dict[str, str],
    fuzzer_name: str,
    base_name: str,
) -> Optional[str]:
    """Last-resort: match by common ``fuzzer_name.{c,cc,cpp,java}`` filenames."""
    wanted = {
        f"{fuzzer_name}.c",
        f"{fuzzer_name}.cc",
        f"{fuzzer_name}.cpp",
        f"{fuzzer_name}.java",
        f"{base_name}.c",
        f"{base_name}.cc",
        f"{base_name}.cpp",
        f"{base_name}.java",
    }
    for path, content in source_files.items():
        if os.path.basename(path) in wanted:
            logger.debug("Name-based fallback match: %s", path)
            return content
    return None


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def find_fuzzer_source(
    fuzzer_path: str,
    project_name: str,
    project_src_dir: str,
    focus: str,
    language: str = "c",
    test_nginx: bool = False,
    llm_client: Optional["LLMClient"] = None,
) -> str:
    """Find the source code for ``fuzzer_path`` using a layered set of heuristics.

    Args:
        fuzzer_path: Absolute path to the fuzzer binary on the host.
        project_name: OSS-Fuzz project name; used to look up build scripts
            under ``fuzz-tooling/projects/{project_name}``.
        project_src_dir: Directory the project source tree lives under.
        focus: Project focus directory name, relative to the project root.
        language: Primary source language (``c``, ``cpp``, ``java``...).
        test_nginx: Special-case for the NGINX test harness used during
            bring-up; if true, returns the hard-coded pov_harness.cc.
        llm_client: Optional LLM client for the smart-identifier fallback.
            When absent, the LLM phase is skipped.

    Returns:
        The source code of the fuzzer, license-stripped, or a one-line
        placeholder comment when discovery fails in every phase.
    """
    if test_nginx:
        nginx_path = "src/harnesses/pov_harness.cc"
        try:
            with open(nginx_path, "r") as fh:
                return fh.read()
        except OSError as exc:
            logger.error("Error reading NGINX harness: %s", exc)
            return ""

    fuzzer_name = os.path.basename(fuzzer_path)
    project_dir = fuzzer_path.split("/fuzz-tooling/build/out")[0] + "/"
    base_name = fuzzer_name.replace("_fuzzer", "") if "_fuzzer" in fuzzer_name else fuzzer_name

    logger.debug("Looking for source of %s in %s", fuzzer_name, project_src_dir)
    extensions = _source_extensions(language)

    # Phase 1: direct LLVMFuzzerTestOneInput scan.
    direct = _find_by_llvm_marker(project_src_dir, extensions)
    if direct is not None:
        return strip_license_text(direct)

    logger.debug("%s not found directly; falling back to build-script discovery", _LLVM_MARKER)

    # Phase 2a: build-script collection.
    build_scripts = _collect_build_scripts(
        project_dir, project_src_dir, focus, project_name, fuzzer_name
    )

    # Dirs referenced inside the build scripts, and extra candidate search
    # locations derived from them. Preserved for behavioural parity with the
    # legacy implementation.
    dirs_from_scripts = _dirs_referenced_in_build_scripts(build_scripts)
    logger.debug("Build scripts referenced %d directories", len(dirs_from_scripts))

    # Phase 3: collect candidate sources under build-script directories plus
    # any fuzz-related directories we can enumerate.
    project_path = os.path.join(project_dir, f"fuzz-tooling/projects/{project_name}")

    source_files: Dict[str, str] = {}

    # Sources co-located with build scripts (short-circuits on name match).
    script_dirs = [os.path.dirname(p) for p in build_scripts]
    early, scoped = _collect_candidate_sources(
        script_dirs, extensions, fuzzer_name, base_name
    )
    if early is not None:
        return strip_license_text(early)
    source_files.update(scoped)

    # Sources referenced by relative directory fragments inside build scripts.
    for dir_from_build in dirs_from_scripts:
        for base in (project_src_dir, os.path.dirname(project_src_dir)):
            search_dir = os.path.join(base, dir_from_build)
            if not (os.path.exists(search_dir) and os.path.isdir(search_dir)):
                continue
            for name in os.listdir(search_dir):
                if not any(name.endswith(ext) for ext in extensions):
                    continue
                path = os.path.join(search_dir, name)
                if path in source_files:
                    continue
                content = _read_file(path)
                if content is not None and len(content) < _MAX_SOURCE_FILE_BYTES:
                    source_files[path] = content
                    logger.debug("Added source from build-referenced dir: %s", path)

    # Broader discovery: unpack pkgs, walk fuzz/ dirs, crawl project_src_dir
    # for anything fuzzer-ish.
    fuzz_dirs = _enumerate_fuzz_dirs(
        project_dir, project_src_dir, focus, build_scripts, project_path
    )
    early, broad = _collect_candidate_sources(fuzz_dirs, extensions, fuzzer_name, base_name)
    if early is not None:
        return strip_license_text(early)
    for path, content in broad.items():
        source_files.setdefault(path, content)

    logger.debug("Collected %d candidate source files", len(source_files))

    llvm_marker_files = {
        p: c for p, c in source_files.items() if _LLVM_MARKER in c
    }
    if len(llvm_marker_files) == 1:
        return strip_license_text(next(iter(llvm_marker_files.values())))

    # Phase 2b: parse build scripts for an explicit source reference.
    parsed = _parse_build_scripts(build_scripts, fuzzer_name)
    if parsed:
        candidates = [parsed, os.path.join(project_src_dir, parsed)]
        if "/" not in parsed:
            for common_dir in ("src", "external", "lib", "fuzz", "test"):
                candidates.append(os.path.join(project_src_dir, common_dir, parsed))
        for cand in candidates:
            if os.path.exists(cand):
                content = _read_file(cand)
                if content is not None and _LLVM_MARKER in content:
                    logger.debug("Build-script-parsed source: %s", cand)
                    return strip_license_text(content)
                if content is not None:
                    logger.warning(
                        "Build-identified file %s does not contain %s", cand, _LLVM_MARKER
                    )

    if len(source_files) == 1:
        only_path = next(iter(source_files))
        logger.debug("Only one candidate; returning %s", only_path)
        return strip_license_text(source_files[only_path])

    source_files = _filter_candidates(source_files, fuzzer_name, base_name)

    # Phase 4: LLM identification.
    if llm_client is not None and len(source_files) > 1:
        llm_result = _identify_via_llm(
            build_scripts,
            source_files,
            llvm_marker_files,
            fuzzer_name,
            base_name,
            fuzzer_path,
            project_src_dir,
            llm_client,
        )
        if llm_result is not None:
            return strip_license_text(llm_result)

    # Phase 5: name-based fallback.
    fallback = _fallback_by_name(source_files, fuzzer_name, base_name)
    if fallback is not None:
        return strip_license_text(fallback)

    logger.warning("Could not identify fuzzer source")
    return "// Could not find the source code for the fuzzer"
