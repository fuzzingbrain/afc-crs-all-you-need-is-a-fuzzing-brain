import os
import argparse
import re
from collections import defaultdict

IF_PATTERN = re.compile(r'^\s*if\b.*[):{;]?$')

def parse_lcov(lcov_path):
    executed = defaultdict(set)
    current_file = None

    with open(lcov_path, 'r') as f:
        for line in f:
            line = line.strip()
            if line.startswith('SF:'):
                current_file = line[3:]
            elif line.startswith('BRDA:') and current_file:
                parts = line[5:].split(',')
                if len(parts) >= 4:
                    line_no, _, _, taken = parts
                    if taken != '-' and taken != '0':
                        try:
                            executed[current_file].add(int(line_no))
                        except ValueError:
                            continue
    return executed

def file_matches(filename, filters):
    return any(filename.endswith(f) for f in filters)

def get_context_ranges(line_numbers, context=3):
    sorted_lines = sorted(line_numbers)
    ranges = []
    start = sorted_lines[0] - context
    end = sorted_lines[0] + context

    for line in sorted_lines[1:]:
        if line - context <= end + 1:
            end = max(end, line + context)
        else:
            ranges.append((max(1, start), end))
            start = line - context
            end = line + context
    ranges.append((max(1, start), end))
    return ranges

def print_if_branch_context(file_path, rel_path, executed_lines):
    try:
        with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
            lines = f.readlines()
    except FileNotFoundError:
        print(f"\n=== {file_path} ===\nFile not found.")
        return

    # Keep only lines with executed "if" statements
    if_lines = [ln for ln in executed_lines if 0 < ln <= len(lines) and IF_PATTERN.match(lines[ln - 1])]

    if not if_lines:
        return

    context_ranges = get_context_ranges(if_lines, context=3)
    printed = set()

    print(f"\n=== {rel_path} ===")
    for start, end in context_ranges:
        for i in range(start, min(end + 1, len(lines) + 1)):
            if i in printed:
                continue
            mark = '✅' if i in if_lines else '   '
            print(f"{i:5d} {mark} | {lines[i - 1].rstrip()}")
            printed.add(i)
        print()

def main():
    parser = argparse.ArgumentParser(description="Show executed if-branches with ±3 lines context.")
    parser.add_argument("--lcov", required=True, help="Path to coverage.lcov file")
    parser.add_argument("--src-root", required=True, help="Path to source root (mapped from /src/project_name)")
    parser.add_argument("--project-name", required=True, help="project_name)")
    parser.add_argument("--files", nargs='*', help="Optional list of file name filters (e.g., html.c xpath.c)")
    args = parser.parse_args()

    file_filters = set(args.files) if args.files else None
    executed = parse_lcov(args.lcov)

    for full_path, lines in executed.items():
        rel_path = os.path.relpath(full_path, f'/src/{args.project_name}')
        filename = os.path.basename(rel_path)

        if file_filters and filename not in file_filters:
            continue

        real_path = os.path.join(args.src_root, rel_path)
        print_if_branch_context(real_path, rel_path, lines)

if __name__ == "__main__":
    main()