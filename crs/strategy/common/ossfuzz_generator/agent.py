#!/usr/bin/env python3
"""
OSS-Fuzz Integration Generator using Claude Agent SDK

This module uses the Claude Agent SDK to automatically generate OSS-Fuzz
integration files (Dockerfile, build.sh, project.yaml, and fuzz harnesses)
for projects that don't have existing OSS-Fuzz support.
"""
import os
import sys
import asyncio
import logging
from pathlib import Path
from typing import Optional, Dict, Any

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


# System prompt for the OSS-Fuzz integration agent
OSSFUZZ_AGENT_SYSTEM_PROMPT = """You are an expert OSS-Fuzz integration specialist. Your task is to analyze a software project and generate the necessary files to integrate it with OSS-Fuzz for fuzz testing.

## Your Goals:
1. Analyze the repository structure to understand the build system and language
2. Identify potential fuzz targets (functions that process untrusted input)
3. Generate a complete OSS-Fuzz integration including:
   - project.yaml: Project metadata
   - Dockerfile: Build environment with all dependencies
   - build.sh: Build script that compiles fuzz targets
   - At least one fuzz harness targeting security-critical code

## Key Requirements:
- The Dockerfile MUST use the appropriate OSS-Fuzz base image:
  - C/C++: gcr.io/oss-fuzz-base/base-builder
  - Java: gcr.io/oss-fuzz-base/base-builder-jvm
  - Python: gcr.io/oss-fuzz-base/base-builder-python
  - Go: gcr.io/oss-fuzz-base/base-builder-go
  - Rust: gcr.io/oss-fuzz-base/base-builder-rust

- The build.sh script MUST:
  - Use $CC, $CXX, $CFLAGS, $CXXFLAGS environment variables
  - Link with $LIB_FUZZING_ENGINE
  - Output fuzzers to $OUT directory
  - Source files are in $SRC

- Fuzz harnesses MUST implement the standard entry point:
  - C/C++: extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
  - Java: public static void fuzzerTestOneInput(FuzzedDataProvider data)

## Process:
1. First, explore the repository to understand its structure
2. Identify the build system (CMake, Make, Autotools, Maven, Gradle, etc.)
3. Find dependencies that need to be installed
4. Locate security-critical code paths (parsers, deserializers, crypto, network handlers)
5. Generate all required files

Be thorough in dependency detection - missing dependencies cause build failures.
"""


def _get_build_fix_prompt(repo_path: str, project_name: str, output_dir: str, build_error: str) -> str:
    """Generate the prompt for fixing a build error."""
    return f"""The OSS-Fuzz integration for "{project_name}" failed to build. Please analyze the error and fix the integration files.

## Build Error Output:
```
{build_error}
```

## Current Files Location:
The integration files are in: {output_dir}/

## Your Task:
1. Read the current Dockerfile, build.sh, and any fuzz harnesses
2. Analyze the build error to understand what went wrong
3. Fix the files to resolve the build error
4. Common issues include:
   - Missing dependencies in Dockerfile
   - Incorrect build commands in build.sh
   - Wrong paths or environment variables
   - CMake/Make configuration issues
   - Missing compiler flags or linker flags
   - Boost version requirements (some projects need >= 1.74.0)

## Important Notes:
- Do NOT add $LIB_FUZZING_ENGINE to CMAKE_EXE_LINKER_FLAGS during CMake configuration (it breaks compiler tests)
- Instead, pass it via project-specific CMake variables like -DFUZZ_LIBS="$LIB_FUZZING_ENGINE"
- Use $SANITIZER (from OSS-Fuzz) for sanitizer configuration, not hardcoded "fuzzer"
- If Boost is too old in base image, build from source using GitHub releases

Please fix the integration files now."""


def _get_project_analysis_prompt(repo_path: str, project_name: str) -> str:
    """Generate the prompt for analyzing a project and creating OSS-Fuzz integration."""
    return f"""Please analyze the repository at {repo_path} and generate a complete OSS-Fuzz integration for the project "{project_name}".

Steps to follow:
1. First, explore the repository structure using ls and find commands to understand:
   - The programming language(s) used
   - The build system (CMake, Make, Autotools, Maven, Gradle, Cargo, etc.)
   - Key source directories
   - Existing test infrastructure

2. Read key files like:
   - README.md for build instructions
   - CMakeLists.txt, Makefile, configure.ac, pom.xml, build.gradle, Cargo.toml, etc.
   - Any existing fuzz tests

3. Identify potential fuzz targets by looking for:
   - Input parsing functions
   - Deserialization code
   - Protocol handlers
   - File format parsers
   - Cryptographic operations
   - Functions that process user/network input

4. Create the following files in the output directory:
   - project.yaml
   - Dockerfile
   - build.sh
   - At least one fuzz harness (e.g., fuzz_target.c or FuzzTarget.java)

The output directory for these files is: {repo_path}/../fuzz-tooling/projects/{project_name}/

Make sure to:
- Install ALL required dependencies in the Dockerfile
- Handle the project's specific build system correctly
- Create fuzz targets that actually exercise security-critical code paths
- Test that the build.sh script logic is correct

Please proceed with the analysis and file generation."""


async def _run_agent_async(
    repo_path: str,
    project_name: str,
    output_dir: str,
    max_turns: int = 30,
) -> bool:
    """Run the Claude agent to generate OSS-Fuzz integration files."""

    if not CLAUDE_SDK_AVAILABLE:
        logger.error("Claude Agent SDK not available")
        return False

    # Ensure output directory exists
    os.makedirs(output_dir, exist_ok=True)

    options = ClaudeAgentOptions(
        system_prompt=OSSFUZZ_AGENT_SYSTEM_PROMPT,
        max_turns=max_turns,
        allowed_tools=["Read", "Write", "Bash", "Glob", "Grep"],
        permission_mode='acceptEdits',  # Auto-accept file edits
        cwd=repo_path,
    )

    prompt = _get_project_analysis_prompt(repo_path, project_name)

    try:
        async with ClaudeSDKClient(options=options) as client:
            await client.query(prompt)

            full_response = []
            async for message in client.receive_response():
                if isinstance(message, AssistantMessage):
                    for block in message.content:
                        if isinstance(block, TextBlock):
                            full_response.append(block.text)
                            logger.info(f"Agent: {block.text[:200]}...")

            # Check if required files were created
            required_files = ['project.yaml', 'Dockerfile', 'build.sh']
            missing_files = []
            for f in required_files:
                if not os.path.exists(os.path.join(output_dir, f)):
                    missing_files.append(f)

            if missing_files:
                logger.warning(f"Agent did not create all required files. Missing: {missing_files}")
                return False

            logger.info(f"Successfully generated OSS-Fuzz integration in {output_dir}")
            return True

    except Exception as e:
        logger.error(f"Agent execution failed: {e}")
        return False


async def _run_fix_agent_async(
    repo_path: str,
    project_name: str,
    output_dir: str,
    build_error: str,
    max_turns: int = 30,
) -> bool:
    """Run the Claude agent to fix OSS-Fuzz build errors."""

    if not CLAUDE_SDK_AVAILABLE:
        logger.error("Claude Agent SDK not available")
        return False

    options = ClaudeAgentOptions(
        system_prompt=OSSFUZZ_AGENT_SYSTEM_PROMPT,
        max_turns=max_turns,
        allowed_tools=["Read", "Write", "Bash", "Glob", "Grep"],
        permission_mode='acceptEdits',
        cwd=repo_path,
    )

    prompt = _get_build_fix_prompt(repo_path, project_name, output_dir, build_error)

    try:
        async with ClaudeSDKClient(options=options) as client:
            await client.query(prompt)

            async for message in client.receive_response():
                if isinstance(message, AssistantMessage):
                    for block in message.content:
                        if isinstance(block, TextBlock):
                            logger.info(f"Agent: {block.text[:200]}...")

            logger.info(f"Agent finished attempting to fix build errors")
            return True

    except Exception as e:
        logger.error(f"Agent execution failed: {e}")
        return False


def fix_build_error(
    repo_path: str,
    project_name: str,
    build_error: str,
    output_dir: Optional[str] = None,
    max_turns: int = 30,
) -> bool:
    """
    Fix OSS-Fuzz build errors using Claude Agent SDK.

    Args:
        repo_path: Path to the cloned repository
        project_name: Name of the project
        build_error: The build error output to fix
        output_dir: Directory containing the integration files
        max_turns: Maximum agent turns (default: 30)

    Returns:
        bool: True if agent completed (doesn't guarantee fix worked)
    """
    if output_dir is None:
        output_dir = os.path.join(
            os.path.dirname(repo_path),
            "fuzz-tooling", "projects", project_name
        )

    logger.info(f"Attempting to fix build error for {project_name}")
    logger.info(f"Output directory: {output_dir}")

    return asyncio.run(_run_fix_agent_async(repo_path, project_name, output_dir, build_error, max_turns))


def generate_ossfuzz_integration(
    repo_path: str,
    project_name: str,
    output_dir: Optional[str] = None,
    max_turns: int = 30,
) -> bool:
    """
    Generate OSS-Fuzz integration files for a project using Claude Agent SDK.

    Args:
        repo_path: Path to the cloned repository
        project_name: Name of the project
        output_dir: Directory to write generated files (default: repo_path/../fuzz-tooling/projects/{project_name})
        max_turns: Maximum agent turns (default: 30)

    Returns:
        bool: True if integration was generated successfully
    """
    if output_dir is None:
        output_dir = os.path.join(
            os.path.dirname(repo_path),
            "fuzz-tooling", "projects", project_name
        )

    logger.info(f"Generating OSS-Fuzz integration for {project_name}")
    logger.info(f"Repository: {repo_path}")
    logger.info(f"Output directory: {output_dir}")

    return asyncio.run(_run_agent_async(repo_path, project_name, output_dir, max_turns))


# CLI entry point
def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Generate OSS-Fuzz integration using Claude Agent SDK"
    )
    parser.add_argument("repo_path", help="Path to the repository")
    parser.add_argument("project_name", help="Name of the project")
    parser.add_argument("--output-dir", help="Output directory for generated files")
    parser.add_argument("--max-turns", type=int, default=30, help="Max agent turns")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument("--fix-error", help="Fix a build error (pass error file path or '-' for stdin)")

    args = parser.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    # Handle fix-error mode
    if args.fix_error:
        if args.fix_error == '-':
            build_error = sys.stdin.read()
        else:
            with open(args.fix_error, 'r') as f:
                build_error = f.read()

        success = fix_build_error(
            args.repo_path,
            args.project_name,
            build_error,
            args.output_dir,
            args.max_turns,
        )
    else:
        success = generate_ossfuzz_integration(
            args.repo_path,
            args.project_name,
            args.output_dir,
            args.max_turns,
        )

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
