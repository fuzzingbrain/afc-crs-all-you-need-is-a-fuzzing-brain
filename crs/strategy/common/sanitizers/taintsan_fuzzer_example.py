#!/usr/bin/env python3
"""
Example: Using TaintSan with Atheris for Security Fuzzing

This demonstrates how TaintSan can detect injection vulnerabilities
during fuzzing by tracking tainted data flow.
"""

import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import taintsan_python as taintsan

# Install TaintSan monitors BEFORE importing target code
taintsan.install()

# Now import the code we want to fuzz
import sqlite3
import subprocess
import json


# ============================================================================
# Vulnerable Functions (for demonstration)
# ============================================================================

def vulnerable_sql_query(user_input: str) -> list:
    """
    VULNERABLE: Directly interpolates user input into SQL query.
    TaintSan will detect this!
    """
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE users (id INTEGER, name TEXT)")
    cursor.execute("INSERT INTO users VALUES (1, 'admin')")

    # VULNERABILITY: SQL Injection
    query = f"SELECT * FROM users WHERE name = '{user_input}'"
    cursor.execute(query)  # TaintSan triggers here!

    return cursor.fetchall()


def vulnerable_command_exec(filename: str) -> str:
    """
    VULNERABLE: Passes user input to shell command.
    TaintSan will detect this!
    """
    # VULNERABILITY: Command Injection
    result = subprocess.run(
        f"cat {filename}",  # TaintSan triggers here!
        shell=True,
        capture_output=True,
        text=True
    )
    return result.stdout


def safe_sql_query(user_input: str) -> list:
    """
    SAFE: Uses parameterized queries.
    TaintSan will NOT trigger because tainted data doesn't reach the query string.
    """
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE users (id INTEGER, name TEXT)")
    cursor.execute("INSERT INTO users VALUES (1, 'admin')")

    # SAFE: Parameterized query - taint doesn't propagate to query string
    query = "SELECT * FROM users WHERE name = ?"
    cursor.execute(query, (str(user_input),))  # str() removes taint wrapper

    return cursor.fetchall()


def process_json_config(json_data: str) -> dict:
    """
    Process JSON configuration - demonstrates taint propagation through parsing.
    """
    try:
        config = json.loads(json_data)

        # If we use tainted data in a dangerous way...
        if 'command' in config:
            cmd = config['command']
            # This would trigger TaintSan if cmd retains taint
            # (Note: json.loads doesn't preserve our taint wrappers,
            #  so we'd need enhanced JSON parsing for full tracking)
            pass

        return config
    except json.JSONDecodeError:
        return {}


# ============================================================================
# Atheris Fuzzing Harness
# ============================================================================

def TestOneInput(data: bytes):
    """
    Atheris fuzzing entry point with TaintSan integration.
    """
    if len(data) < 1:
        return

    # Mark fuzzer input as tainted
    tainted_data = taintsan.taint_from_fuzzer(data)

    try:
        # Decode to string (taint propagates)
        tainted_str = tainted_data.decode('utf-8', errors='ignore')

        # Test various vulnerable functions
        # Uncomment one at a time to test:

        # Test 1: SQL Injection detection
        # vulnerable_sql_query(tainted_str)  # Will raise TaintViolationError

        # Test 2: Command Injection detection
        # vulnerable_command_exec(tainted_str)  # Will raise TaintViolationError

        # Test 3: Safe version (no violation)
        safe_sql_query(tainted_str)

        # Test 4: String operations preserve taint
        modified = tainted_str.strip().lower()
        parts = modified.split(',')

        # Demonstrate taint propagation
        for part in parts:
            if taintsan.is_tainted(part):
                # This part came from fuzzer input
                pass

    except taintsan.TaintViolationError as e:
        # TaintSan detected a vulnerability!
        # In fuzzing mode, we want to report this as a finding
        print(f"\n[TAINTSAN] Vulnerability detected: {e}", file=sys.stderr)
        raise  # Re-raise so Atheris records it as a crash

    except Exception as e:
        # Other exceptions (parsing errors, etc.) - expected during fuzzing
        pass


# ============================================================================
# Main: Run with Atheris or standalone demo
# ============================================================================

def run_demo():
    """Demonstrate TaintSan without Atheris"""
    print("=" * 60)
    print("TaintSan Demo - Taint Tracking for Python")
    print("=" * 60)

    # Simulate fuzzer input
    test_inputs = [
        b"normal_user",
        b"'; DROP TABLE users; --",
        b"/etc/passwd",
        b"$(whoami)",
        b'{"command": "rm -rf /"}',
    ]

    for data in test_inputs:
        print(f"\n--- Testing input: {data[:50]}... ---")

        tainted = taintsan.taint_from_fuzzer(data)
        tainted_str = tainted.decode('utf-8', errors='ignore')

        print(f"  Input tainted: {taintsan.is_tainted(tainted_str)}")

        # Test taint propagation
        modified = "prefix_" + tainted_str + "_suffix"
        print(f"  After concat tainted: {taintsan.is_tainted(modified)}")

        upper = tainted_str.upper()
        print(f"  After upper() tainted: {taintsan.is_tainted(upper)}")

        # Test safe function (no violation)
        try:
            result = safe_sql_query(tainted_str)
            print(f"  Safe query succeeded: {result}")
        except Exception as e:
            print(f"  Safe query error: {e}")

        # Test vulnerable function (should trigger violation)
        try:
            # Uncomment to test SQL injection detection:
            # result = vulnerable_sql_query(tainted_str)
            # print(f"  Vulnerable query succeeded (BAD!): {result}")
            pass
        except taintsan.TaintViolationError as e:
            print(f"  [GOOD] TaintSan caught vulnerability: {e}")
        except Exception as e:
            print(f"  Other error: {e}")

    # Print summary
    violations = taintsan.get_violations()
    print(f"\n{'=' * 60}")
    print(f"Total violations detected: {len(violations)}")
    for v in violations:
        print(f"  - {v.sink_type.name}: {v.sink_function}")
    print("=" * 60)


if __name__ == "__main__":
    # Check if we should run with Atheris
    if len(sys.argv) > 1 and sys.argv[1] == "--fuzz":
        try:
            import atheris

            # Configure TaintSan for fuzzing mode
            taintsan.TaintSanConfig.RAISE_ON_SINK = True
            taintsan.TaintSanConfig.LOG_VIOLATIONS = True

            print("[TaintSan] Starting Atheris fuzzing with taint tracking...")
            atheris.Setup(sys.argv[1:], TestOneInput)
            atheris.Fuzz()

        except ImportError:
            print("Atheris not installed. Run: pip install atheris")
            print("Running demo mode instead...")
            run_demo()
    else:
        # Run demo without fuzzing
        run_demo()
