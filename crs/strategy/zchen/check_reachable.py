#!/usr/bin/env python3
import argparse
import json
import sys
import os
from litellm import completion
CLAUDE_MODEL_SONNET_4 = "claude-sonnet-4-20250514"
CLAUDE_MODEL_OPUS_4 = "claude-opus-4-20250514"


def call_claude(messages, model_name=CLAUDE_MODEL_OPUS_4):
    try:
        response = completion(
            model=model_name,
            messages=messages,
            max_tokens=4096
        )
        return response["choices"][0]["message"]["content"], True
    except Exception as e:
        return f"Exception: {str(e)}", False

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
    messages = [
        {"role": "system", "content": "You are a helpful assistant."},
        {"role": "user", "content": "Explain fuzzing in simple terms."}
    ]
    text, ok = call_claude(messages)
    print("Success:", ok)
    print("Output:", text)
    main()