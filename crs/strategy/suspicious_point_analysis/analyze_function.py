#!/usr/bin/env python3
"""
Analyze a single function to identify suspicious points using LLM.
Uses sliding window over call chain for context.
"""

import json
import os
from typing import List, Dict, Any, Optional


def analyze_function(
    target_function: Dict[str, Any],
    call_chain_functions: List[Dict[str, Any]],
    window_size: int = 3,
    model: str = "claude-sonnet-4-20250514"
) -> List[Dict[str, Any]]:
    """
    Analyze a function and identify suspicious points.

    Args:
        target_function: The function to analyze (ReachableFunction dict)
        call_chain_functions: All functions in the call chain (ordered from entry to target)
        window_size: Number of caller functions to include as context
        model: LLM model to use

    Returns:
        List of suspicious points found in this function
    """
    # Extract context: last N functions before target (sliding window)
    context_functions = call_chain_functions[-(window_size + 1):-1] if len(call_chain_functions) > 1 else []

    # Build prompt
    prompt = build_analysis_prompt(target_function, context_functions)

    # Call LLM
    response = call_llm(prompt, model)

    # Parse response into structured suspicious points
    suspicious_points = parse_llm_response(response, target_function)

    return suspicious_points


def build_analysis_prompt(
    target_function: Dict[str, Any],
    context_functions: List[Dict[str, Any]]
) -> str:
    """
    Build the LLM prompt with sliding window context.
    """
    function_name = target_function.get("function_name", "unknown")
    file_path = target_function.get("file_path", "")
    signature = target_function.get("signature", "")
    function_body = target_function.get("function_body", "")

    # Build context section
    context_section = ""
    if context_functions:
        context_section = "\n## Call Chain Context:\n"
        for i, func in enumerate(context_functions, 1):
            context_section += f"{i}. {func.get('function_name', 'unknown')}() in {func.get('file_path', '')}\n"
        context_section += f"{len(context_functions) + 1}. {function_name}() [TARGET FUNCTION]\n"

    prompt = f"""You are a security expert analyzing code for vulnerabilities.

# Task
Analyze the following function `{function_name}` and identify ALL suspicious points that could lead to security vulnerabilities.

{context_section}

# Function to Analyze
File: {file_path}
Signature: {signature}

```
{function_body if function_body else "[Function body not available - analyze based on signature]"}
```

# Instructions
For EACH suspicious point you find, provide:
1. **vuln_type**: Type of vulnerability (buffer_overflow, use_after_free, integer_overflow, null_dereference, etc.)
2. **location**: Exact line or code snippet where the issue occurs
3. **reason**: WHY this is suspicious (be specific)
4. **severity**: high, medium, or low
5. **cwe**: CWE identifier if applicable (e.g., CWE-119)
6. **attack_vector**: How an attacker could exploit this

# Output Format
Return a JSON array of suspicious points:

```json
[
  {{
    "vuln_type": "buffer_overflow",
    "location": "line 45: memcpy(dest, src, len)",
    "reason": "No bounds checking on 'len' parameter, could write beyond buffer",
    "severity": "high",
    "cwe": "CWE-119",
    "attack_vector": "Attacker can provide large 'len' value to overflow dest buffer"
  }}
]
```

If NO suspicious points found, return an empty array: []

IMPORTANT: Return ONLY the JSON array, no additional text.
"""

    return prompt


def call_llm(prompt: str, model: str) -> str:
    """
    Call Anthropic API and return response.
    """
    import anthropic
    from dotenv import load_dotenv

    # Try to load from .env file
    load_dotenv()

    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        raise ValueError("ANTHROPIC_API_KEY not found in environment variables")

    client = anthropic.Anthropic(api_key=api_key)

    print(f"[INFO] Calling Anthropic API with model: {model}")
    print(f"[INFO] Prompt length: {len(prompt)} chars")

    try:
        response = client.messages.create(
            model=model,
            max_tokens=4096,
            temperature=0,
            messages=[
                {
                    "role": "user",
                    "content": prompt
                }
            ]
        )

        # Extract text from response
        content = response.content[0].text
        return content

    except Exception as e:
        print(f"[ERROR] LLM API call failed: {e}")
        raise


def parse_llm_response(response: str, target_function: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Parse LLM response into structured suspicious points.
    """
    try:
        # Extract JSON from response (handle cases where LLM adds extra text)
        response = response.strip()

        # Find JSON array
        start_idx = response.find('[')
        end_idx = response.rfind(']') + 1

        if start_idx == -1 or end_idx == 0:
            print(f"[WARNING] No JSON array found in response")
            return []

        json_str = response[start_idx:end_idx]
        suspicious_points = json.loads(json_str)

        # Enrich with function metadata
        for point in suspicious_points:
            point["function_name"] = target_function.get("function_name", "")
            point["file_path"] = target_function.get("file_path", "")
            point["call_path"] = target_function.get("call_path", [])

        return suspicious_points

    except json.JSONDecodeError as e:
        print(f"[ERROR] Failed to parse LLM response as JSON: {e}")
        print(f"[ERROR] Response was: {response[:200]}...")
        return []


def format_to_jsonl(suspicious_points: List[Dict[str, Any]], output_file: str):
    """
    Format suspicious points to JSONL file.
    """
    with open(output_file, 'w') as f:
        for point in suspicious_points:
            f.write(json.dumps(point) + '\n')

    print(f"[INFO] Wrote {len(suspicious_points)} suspicious points to {output_file}")


# Example usage
if __name__ == "__main__":
    # Example function
    target = {
        "function_name": "memcpy_wrapper",
        "file_path": "src/utils.c",
        "start_line": 45,
        "end_line": 52,
        "call_path": ["main", "process_data", "memcpy_wrapper"],
        "signature": "void* memcpy_wrapper(void* dest, const void* src, size_t n)",
        "function_body": """void* memcpy_wrapper(void* dest, const void* src, size_t n) {
    if (!dest || !src) {
        return NULL;
    }
    return memcpy(dest, src, n);
}"""
    }

    # Mock call chain (would be loaded from JSONL in real usage)
    call_chain = [
        {"function_name": "main", "file_path": "main.c"},
        {"function_name": "process_data", "file_path": "process.c"},
        target
    ]

    # Analyze
    results = analyze_function(target, call_chain, window_size=2)

    # Output
    print(json.dumps(results, indent=2))
