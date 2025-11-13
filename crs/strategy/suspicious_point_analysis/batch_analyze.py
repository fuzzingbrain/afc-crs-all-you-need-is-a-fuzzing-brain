#!/usr/bin/env python3
"""
Batch process all functions from reachable_functions.jsonl
and generate suspicious_points.jsonl
"""

import json
import os
import sys
import argparse
from typing import List, Dict, Any
from analyze_function import analyze_function, format_to_jsonl


def load_functions_from_jsonl(input_file: str) -> List[Dict[str, Any]]:
    """
    Load all functions from JSONL file.
    """
    functions = []
    with open(input_file, 'r') as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                func = json.loads(line)
                functions.append(func)
            except json.JSONDecodeError as e:
                print(f"[WARNING] Failed to parse line {line_num}: {e}")
                continue

    print(f"[INFO] Loaded {len(functions)} functions from {input_file}")
    return functions


def build_call_chain_context(functions: List[Dict[str, Any]], target_function: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Build call chain context for a target function.
    Uses the call_path field to find caller functions.
    """
    call_path = target_function.get("call_path", [])
    if not call_path:
        return [target_function]

    # Build a map of function_name -> function
    func_map = {f.get("function_name"): f for f in functions}

    # Extract functions in call path
    chain = []
    for func_name in call_path:
        if func_name in func_map:
            chain.append(func_map[func_name])
        else:
            # If function not in our list, create a stub
            chain.append({"function_name": func_name})

    return chain


def batch_analyze(
    input_file: str,
    output_file: str,
    window_size: int = 3,
    model: str = "claude-sonnet-4-20250514",
    max_functions: int = None
):
    """
    Batch analyze all functions and output suspicious points.

    Args:
        input_file: Path to reachable_functions.jsonl
        output_file: Path to output suspicious_points.jsonl
        window_size: Sliding window size for context
        model: LLM model to use
        max_functions: Maximum number of functions to analyze (for testing)
    """
    print(f"[INFO] Starting batch analysis")
    print(f"[INFO] Input: {input_file}")
    print(f"[INFO] Output: {output_file}")
    print(f"[INFO] Model: {model}")
    print(f"[INFO] Window size: {window_size}")

    # Load all functions
    functions = load_functions_from_jsonl(input_file)

    if not functions:
        print("[ERROR] No functions loaded, exiting")
        return

    # Limit for testing
    if max_functions:
        functions = functions[:max_functions]
        print(f"[INFO] Limited to first {max_functions} functions for testing")

    # Analyze each function
    all_suspicious_points = []
    total = len(functions)

    for idx, func in enumerate(functions, 1):
        func_name = func.get("function_name", "unknown")
        file_path = func.get("file_path", "")

        print(f"\n[{idx}/{total}] Analyzing: {func_name} in {file_path}")

        try:
            # Build call chain context
            call_chain = build_call_chain_context(functions, func)

            # Analyze this function
            suspicious_points = analyze_function(
                target_function=func,
                call_chain_functions=call_chain,
                window_size=window_size,
                model=model
            )

            if suspicious_points:
                print(f"[INFO] Found {len(suspicious_points)} suspicious point(s)")
                all_suspicious_points.extend(suspicious_points)
            else:
                print(f"[INFO] No suspicious points found")

        except Exception as e:
            print(f"[ERROR] Failed to analyze {func_name}: {e}")
            # Continue with next function
            continue

    # Write all results to output file
    print(f"\n[INFO] Analysis complete!")
    print(f"[INFO] Total suspicious points: {len(all_suspicious_points)}")

    with open(output_file, 'w') as f:
        for point in all_suspicious_points:
            f.write(json.dumps(point) + '\n')

    print(f"[INFO] Results written to {output_file}")


def main():
    parser = argparse.ArgumentParser(
        description="Batch analyze functions to identify suspicious points"
    )
    parser.add_argument(
        "input_file",
        help="Path to reachable_functions.jsonl"
    )
    parser.add_argument(
        "-o", "--output",
        default="suspicious_points.jsonl",
        help="Output file path (default: suspicious_points.jsonl)"
    )
    parser.add_argument(
        "-w", "--window-size",
        type=int,
        default=3,
        help="Sliding window size for call chain context (default: 3)"
    )
    parser.add_argument(
        "-m", "--model",
        default="claude-sonnet-4-20250514",
        help="LLM model to use (default: claude-sonnet-4-20250514)"
    )
    parser.add_argument(
        "--max-functions",
        type=int,
        help="Maximum number of functions to analyze (for testing)"
    )

    args = parser.parse_args()

    # Check input file exists
    if not os.path.exists(args.input_file):
        print(f"[ERROR] Input file not found: {args.input_file}")
        sys.exit(1)

    # Run batch analysis
    batch_analyze(
        input_file=args.input_file,
        output_file=args.output,
        window_size=args.window_size,
        model=args.model,
        max_functions=args.max_functions
    )


if __name__ == "__main__":
    main()
