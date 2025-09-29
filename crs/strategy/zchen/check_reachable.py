#!/usr/bin/env python3
import argparse
import json
import sys

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--static_result", required=True)
    args = parser.parse_args()

    vuln_func = "g_clear_object"

    with open(args.static_result, "r", encoding="utf-8") as f:
        data = json.load(f)

    reachable = data.get("reachable", {})

    found_entry = None
    for entry, funcs in reachable.items():
        if vuln_func in funcs:
            found_entry = entry
            break

    if found_entry:
        print("Reachable!")
        print(f"{vuln_func} is reachable from {found_entry}")
    else:
        print("Not reachable")
        print(f"{vuln_func} is NOT reachable from any entrypoint")

if __name__ == "__main__":
    main()