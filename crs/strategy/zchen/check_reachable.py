#!/usr/bin/env python3
import argparse
import json
import sys
import os
from litellm import completion
CLAUDE_MODEL_SONNET_4 = "claude-sonnet-4-20250514"
CLAUDE_MODEL_OPUS_4 = "claude-opus-4-20250514"

def find_fuzzer_source():
    """Find the source code of the fuzzer by using the model to analyze build scripts and source files"""

    # HARD-CODED for f
    fuzzer_code = """
    /*
 * Copyright 2024 Richard Hughes <richard@hughsie.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#include <glib.h>

#include "libfwupdplugin/fu-elf-firmware.h"

int
main(int argc, char **argv)
{
	g_autoptr(FuFirmware) firmware = FU_FIRMWARE(g_object_new(FU_TYPE_ELF_FIRMWARE, NULL));
	g_autoptr(GBytes) blob_dst = NULL;
	g_autoptr(GError) error = NULL;

	/* do not use g_option_context_parse() here for speed */
	if (argc != 3 || !g_str_has_suffix(argv[1], ".builder.xml") ||
	    !g_str_has_suffix(argv[2], ".bin")) {
		g_printerr("Invalid arguments, expected %s XML BIN\n", argv[0]);
		return EXIT_FAILURE;
	}
	if (!fu_firmware_build_from_filename(firmware, argv[1], &error)) {
		g_printerr("Failed to build: %s\n", error->message);
		return EXIT_FAILURE;
	}
	blob_dst = fu_firmware_write(firmware, &error);
	if (blob_dst == NULL) {
		g_printerr("Failed to write: %s\n", error->message);
		return EXIT_FAILURE;
	}
	if (!g_file_set_contents(argv[2],
				 g_bytes_get_data(blob_dst, NULL),
				 g_bytes_get_size(blob_dst),
				 &error)) {
		g_printerr("Failed to save: %s\n", error->message);
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}

    """
    return fuzzer_code


def prompt_template(
        diff_content: str | None = None,
        harness: str | None = None,
    ) -> list[dict]:
    diff_snippet = diff_content if diff_content is not None else "<PASTE COMMIT DIFF HERE IF AVAILABLE>"
    harness_snippet = harness if harness is not None else (
        "// Paste the fuzzer/harness code that reads x.bin here, or describe how x.bin is parsed.\n"
        "// Example: the harness reads whole file as blob; or it expects header: magic(4)|len(4)|payload."
    )

    system_msg = (
        "You are a world-leading software vulnerability detection expert. "
        "Be concise, do not apologize, and do not invent facts. When unsure, explicitly list assumptions. "
        "Prefer producing verifiable, runnable artifacts. Output only what is requested."
    )

    user_msg = (
        "Task: From the commit diff and harness description below, identify the single most likely "
        "vulnerable function name (one C symbol / identifier) that an exploit or malformed input would hit.\n\n"
        "CONTEXT:\n"
        "Commit diff:\n"
        f"{diff_snippet}\n\n"
        "Harness:\n"
        f"{harness_snippet}\n\n"
        "OUTPUT RULES (must follow exactly):\n"
        "(1) Output exactly ONE function name (e.g. g_clear_object).\n"
        "(2) Do NOT output any explanation, punctuation, quotes, code blocks, or extra text.\n"
        "(3) If uncertain, pick the single-best guess and output it anyway.\n"
        "(4) If you cannot extract any plausible function name, output the single token: UNKNOWN\n\n"
        "Remember: only a single token on output, nothing else."
    )

    return [
        {"role": "system", "content": system_msg},
        {"role": "user", "content": user_msg},
    ]

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
    parser.add_argument("--project_parent_dir", required=True)
    parser.add_argument("--focus", required=True)
    args = parser.parse_args()

    vuln_func = "UNKNOWN"

    static_result_path = os.path.join(args.project_parent_dir, args.focus + ".json")
    if not os.path.exists(static_result_path):
        print(f"Static result file does not exist: {static_result_path}")
        sys.exit(1)

    diff_content = None
    diff_path = os.path.join(args.project_parent_dir, "diff", "ret.diff")
    if os.path.exists(diff_path):
        with open(diff_path, "r", encoding="utf-8") as f:
            diff_content = f.read()

    messages = prompt_template(diff_content=diff_content, harness=find_fuzzer_source())
    vuln_func, ok = call_claude(messages)
    print("Success:", ok)
    print("Output:", vuln_func)

    with open(static_result_path, "r", encoding="utf-8") as f:
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