#!/usr/bin/env python3
"""
Security Analyzer using Claude Agent SDK

This module uses the Claude Agent SDK to analyze code for potential security
vulnerabilities and verify them by generating inputs that trigger sanitizer errors
or creating test cases that prove the vulnerability.
"""
import os
import sys
import json
import asyncio
import logging
import subprocess
import tempfile
from pathlib import Path
from typing import Optional, Dict, Any, List

try:
    from claude_agent_sdk import (
        ClaudeSDKClient,
        ClaudeAgentOptions,
        AssistantMessage,
        TextBlock,
        tool,
        create_sdk_mcp_server,
    )
    CLAUDE_SDK_AVAILABLE = True
except ImportError:
    CLAUDE_SDK_AVAILABLE = False
    logging.warning("claude-agent-sdk not installed. Run: pip install claude-agent-sdk")

logger = logging.getLogger(__name__)


SECURITY_ANALYZER_SYSTEM_PROMPT = """You are an expert security researcher specializing in vulnerability discovery and exploitation. Your task is to analyze code, identify potential security vulnerabilities, and VERIFY them by generating inputs that trigger the bugs.

## Your Goals:
1. Analyze the source code and static analysis results to identify potential vulnerabilities
2. For each potential vulnerability, generate a PROOF:
   - Create a fuzzer seed input that will trigger the vulnerability
   - OR create a minimal test case that demonstrates the bug
3. Verify your findings by running the fuzzer with your generated input

## Vulnerability Types to Look For:
- Buffer overflows (stack and heap)
- Integer overflows/underflows
- Use-after-free
- Double-free
- Null pointer dereferences
- Format string vulnerabilities
- Race conditions
- Memory leaks leading to DoS
- Out-of-bounds reads/writes
- Type confusion
- Uninitialized memory use

## Verification Process:
1. Identify a potential vulnerability in the code
2. Understand what input would trigger it
3. Generate a seed input file (binary or text) that exercises the vulnerable code path
4. Run the fuzzer with your seed input to verify it triggers a sanitizer error
5. If the fuzzer doesn't crash, refine your input and try again

## Available Tools:
- Read files to analyze source code
- Write files to create seed inputs
- Run bash commands to execute fuzzers and check for crashes
- Grep to search for vulnerable patterns

## Output Format:
For each verified vulnerability, output a JSON block like:
```json
{
  "vulnerability_type": "buffer-overflow",
  "location": "src/parser.c:123",
  "description": "Stack buffer overflow in parse_header() when input > 256 bytes",
  "seed_input_path": "/path/to/seed_input",
  "verification": "Fuzzer crashed with ASAN: stack-buffer-overflow",
  "severity": "high"
}
```

Be persistent - if your first input doesn't trigger the bug, analyze the fuzzer output and refine your approach.
"""


def _get_analysis_prompt(
    repo_path: str,
    fuzzer_paths: List[str],
    sanitizer: str,
    static_analysis_path: Optional[str] = None,
    diff_path: Optional[str] = None,
    project_name: Optional[str] = None,
    docker_image: Optional[str] = None,
    fuzz_dir: Optional[str] = None,
    work_dir: Optional[str] = None,
) -> str:
    """Generate the prompt for security analysis."""

    # Build fuzzer list for the prompt
    fuzzer_list = "\n".join([f"  - {fp} (target: {os.path.basename(fp)})" for fp in fuzzer_paths])

    prompt = f"""Analyze the code in {repo_path} to find and VERIFY security vulnerabilities.

## Available Fuzzers ({len(fuzzer_paths)} total):
{fuzzer_list}

## Sanitizer: {sanitizer}

"""

    # Add Docker execution instructions if available
    if docker_image and fuzz_dir and project_name:
        prompt += f"""## How to Run Fuzzers (via Docker):
The fuzzers are built with sanitizers and MUST be run inside Docker. Use this command pattern:

```bash
docker run --rm --platform linux/amd64 \\
  -e FUZZING_ENGINE=libfuzzer \\
  -e SANITIZER={sanitizer} \\
  -e ARCHITECTURE=x86_64 \\
  -e PROJECT_NAME={project_name} \\
  -v {repo_path}:/src/{project_name} \\
  -v {fuzz_dir}:/out \\
  -v {work_dir or '/tmp/work'}:/work \\
  {docker_image} \\
  /out/<fuzzer_name> -timeout=30 -timeout_exitcode=99 /out/<seed_file>
```

### Example with a specific fuzzer:
```bash
docker run --rm --platform linux/amd64 \\
  -e FUZZING_ENGINE=libfuzzer \\
  -e SANITIZER={sanitizer} \\
  -e ARCHITECTURE=x86_64 \\
  -e PROJECT_NAME={project_name} \\
  -v {repo_path}:/src/{project_name} \\
  -v {fuzz_dir}:/out \\
  -v {work_dir or '/tmp/work'}:/work \\
  {docker_image} \\
  /out/{os.path.basename(fuzzer_paths[0]) if fuzzer_paths else 'fuzzer'} -timeout=30 /out/my_seed.bin
```

### Steps to verify a vulnerability:
1. Create your seed input file in {fuzz_dir} (e.g., {fuzz_dir}/seed_vuln1.bin)
2. Run the Docker command with that seed file
3. Look for sanitizer output like "ERROR: AddressSanitizer" or "SUMMARY: AddressSanitizer"

"""
    else:
        prompt += """## How to Run Fuzzers:
- Each fuzzer targets a specific functionality (the fuzzer name hints at what it tests)
- To run a fuzzer with a seed input: <fuzzer_path> <seed_file>
- To run with timeout: timeout 30 <fuzzer_path> <seed_file>
- Choose the most appropriate fuzzer based on the vulnerability you're trying to trigger

"""

    prompt += """## Your Task:
1. First, explore the codebase to understand its structure
2. Look for functions that process untrusted input (parsers, deserializers, network handlers)
3. Identify potential vulnerabilities
4. For EACH potential vulnerability:
   a. Determine which fuzzer is most likely to exercise the vulnerable code path
   b. Create a seed input file designed to trigger the bug
   c. Run the appropriate fuzzer with your seed input (use Docker command above)
   d. Check if it triggered a sanitizer error (ASAN, MSAN, UBSAN)
   e. If not, try a different fuzzer or refine your input

"""

    if static_analysis_path and os.path.exists(static_analysis_path):
        prompt += f"""
## Static Analysis Results:
Review the static analysis results at: {static_analysis_path}
These may contain hints about vulnerable code paths.
"""

    if diff_path and os.path.exists(diff_path):
        prompt += f"""
## Code Changes (Diff):
A diff of recent changes is available at: {diff_path}
Focus on analyzing the changed code for newly introduced vulnerabilities.
"""

    prompt += """
## Important:
- Generate BINARY seed inputs when needed (use python or printf in bash)
- Test edge cases: empty input, very large input, malformed structures
- Look for integer boundaries: 0, -1, MAX_INT, MIN_INT
- Try special characters: null bytes, newlines, format specifiers
- Verify EVERY finding by actually running the fuzzer

Start your analysis now. For each vulnerability you find, verify it with the fuzzer before reporting."""

    return prompt


async def _run_security_agent_async(
    repo_path: str,
    fuzzer_paths: List[str],
    sanitizer: str,
    output_dir: str,
    static_analysis_path: Optional[str] = None,
    diff_path: Optional[str] = None,
    max_turns: int = 50,
    project_name: Optional[str] = None,
    docker_image: Optional[str] = None,
    fuzz_dir: Optional[str] = None,
    work_dir: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Run the Claude agent to find and verify security vulnerabilities."""

    if not CLAUDE_SDK_AVAILABLE:
        print("[SecurityAnalyzer] ERROR: Claude Agent SDK not available", flush=True)
        return []

    if not fuzzer_paths:
        print("[SecurityAnalyzer] ERROR: No fuzzers provided", flush=True)
        return []

    os.makedirs(output_dir, exist_ok=True)

    options = ClaudeAgentOptions(
        system_prompt=SECURITY_ANALYZER_SYSTEM_PROMPT,
        max_turns=max_turns,
        allowed_tools=["Read", "Write", "Bash", "Glob", "Grep"],
        permission_mode='acceptEdits',
        cwd=repo_path,
    )

    prompt = _get_analysis_prompt(
        repo_path, fuzzer_paths, sanitizer, static_analysis_path, diff_path,
        project_name, docker_image, fuzz_dir, work_dir
    )

    vulnerabilities = []
    full_response = []

    try:
        async with ClaudeSDKClient(options=options) as client:
            await client.query(prompt)

            async for message in client.receive_response():
                if isinstance(message, AssistantMessage):
                    for block in message.content:
                        if isinstance(block, TextBlock):
                            full_response.append(block.text)
                            # Print truncated agent response
                            preview = block.text[:200].replace('\n', ' ')
                            print(f"[SecurityAnalyzer] Agent: {preview}...", flush=True)

                            # Try to extract vulnerability reports from the response
                            text = block.text
                            if '"vulnerability_type"' in text:
                                # Try to parse JSON blocks
                                import re
                                json_pattern = r'\{[^{}]*"vulnerability_type"[^{}]*\}'
                                matches = re.findall(json_pattern, text, re.DOTALL)
                                for match in matches:
                                    try:
                                        vuln = json.loads(match)
                                        if vuln.get('verification') and 'crash' in vuln.get('verification', '').lower():
                                            vulnerabilities.append(vuln)
                                            print(f"[SecurityAnalyzer] Found verified vulnerability: {vuln.get('vulnerability_type')} at {vuln.get('location')}", flush=True)
                                    except json.JSONDecodeError:
                                        pass

        # Save results
        results_file = os.path.join(output_dir, "security_findings.json")
        with open(results_file, 'w') as f:
            json.dump({
                'vulnerabilities': vulnerabilities,
                'full_response': '\n'.join(full_response)
            }, f, indent=2)

        print(f"[SecurityAnalyzer] Found {len(vulnerabilities)} verified vulnerabilities", flush=True)
        return vulnerabilities

    except Exception as e:
        print(f"[SecurityAnalyzer] ERROR: Security analysis failed: {e}", flush=True)
        return []


def analyze_and_verify_vulnerabilities(
    repo_path: str,
    fuzzer_paths: List[str],
    sanitizer: str = "address",
    output_dir: Optional[str] = None,
    static_analysis_path: Optional[str] = None,
    diff_path: Optional[str] = None,
    max_turns: int = 50,
    project_name: Optional[str] = None,
    docker_image: Optional[str] = None,
    fuzz_dir: Optional[str] = None,
    work_dir: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Analyze code for security vulnerabilities and verify them using fuzzers.

    Args:
        repo_path: Path to the repository
        fuzzer_paths: List of paths to fuzzer binaries (can use any for verification)
        sanitizer: Sanitizer being used (address, memory, undefined)
        output_dir: Directory to store findings
        static_analysis_path: Path to static analysis results (optional)
        diff_path: Path to diff file for delta analysis (optional)
        max_turns: Maximum agent turns
        project_name: OSS-Fuzz project name for Docker execution
        docker_image: Docker image to use for running fuzzers
        fuzz_dir: Directory containing fuzzers (mounted as /out in Docker)
        work_dir: Work directory (mounted as /work in Docker)

    Returns:
        List of verified vulnerability dictionaries
    """
    if output_dir is None:
        output_dir = os.path.join(repo_path, "..", "security_findings")

    # Use print for clean, aligned output
    print(f"[SecurityAnalyzer] Starting analysis for {repo_path}", flush=True)
    print(f"[SecurityAnalyzer] Fuzzers available: {len(fuzzer_paths)}", flush=True)
    for fp in fuzzer_paths:
        print(f"[SecurityAnalyzer]   - {fp}", flush=True)
    print(f"[SecurityAnalyzer] Sanitizer: {sanitizer}", flush=True)
    if docker_image:
        print(f"[SecurityAnalyzer] Docker image: {docker_image}", flush=True)

    return asyncio.run(_run_security_agent_async(
        repo_path, fuzzer_paths, sanitizer, output_dir,
        static_analysis_path, diff_path, max_turns,
        project_name, docker_image, fuzz_dir, work_dir
    ))


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Analyze code for security vulnerabilities using Claude Agent"
    )
    parser.add_argument("repo_path", help="Path to the repository")
    parser.add_argument("--fuzzer", action="append", dest="fuzzers",
                        help="Path to a fuzzer binary (can specify multiple times)")
    parser.add_argument("--sanitizer", default="address", help="Sanitizer type")
    parser.add_argument("--output-dir", help="Output directory for findings")
    parser.add_argument("--static-analysis", help="Path to static analysis results")
    parser.add_argument("--diff", help="Path to diff file for delta analysis")
    parser.add_argument("--max-turns", type=int, default=50, help="Max agent turns")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    # Docker execution settings
    parser.add_argument("--project-name", help="OSS-Fuzz project name for Docker execution")
    parser.add_argument("--docker-image", help="Docker image for running fuzzers")
    parser.add_argument("--fuzz-dir", help="Directory containing fuzzers (mounted as /out)")
    parser.add_argument("--work-dir", help="Work directory (mounted as /work)")

    args = parser.parse_args()

    # Configure logging - use simple format to avoid alignment issues
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(message)s",
        stream=sys.stderr,
        force=True  # Override any existing config
    )

    fuzzer_paths = args.fuzzers or []
    if not fuzzer_paths:
        parser.error("At least one --fuzzer is required")

    vulnerabilities = analyze_and_verify_vulnerabilities(
        args.repo_path,
        fuzzer_paths,
        args.sanitizer,
        args.output_dir,
        args.static_analysis,
        args.diff,
        args.max_turns,
        args.project_name,
        args.docker_image,
        args.fuzz_dir,
        args.work_dir,
    )

    print(f"\n{'='*60}")
    print(f"SECURITY ANALYSIS COMPLETE")
    print(f"{'='*60}")
    print(f"Found {len(vulnerabilities)} verified vulnerabilities")

    for vuln in vulnerabilities:
        print(f"\n[{vuln.get('severity', 'unknown').upper()}] {vuln.get('vulnerability_type')}")
        print(f"  Location: {vuln.get('location')}")
        print(f"  Description: {vuln.get('description')}")
        print(f"  Verification: {vuln.get('verification')}")

    sys.exit(0 if len(vulnerabilities) > 0 else 1)


if __name__ == "__main__":
    main()
