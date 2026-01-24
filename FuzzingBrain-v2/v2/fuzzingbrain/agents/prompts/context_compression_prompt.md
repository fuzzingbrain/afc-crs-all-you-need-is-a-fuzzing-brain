Compress tool results from a security analysis conversation. Keep only what's relevant to the agent's current task.

## Task Background
{task_context}

## What to Keep
{compression_criteria}

## Messages to Compress
{messages_text}

## Output Format

For EACH tool call, output in this format:

### If the result is USEFUL:
```
Tool: {tool_name}({key_args})
Signature: {function_signature_if_code}
Useful:
  - Line X: {relevant_code_line}
  - Line Y: {another_relevant_line}
  - {key_finding}
```

### If the result is NOT USEFUL:
```
Tool: {tool_name}({key_args})
[checked, not relevant]
```

## Rules
1. For code: extract function signature + only lines relevant to the task (with line numbers)
2. For search results: keep only relevant matches
3. For other tools: summarize key findings in 1-2 lines
4. Preserve the agent's reasoning about what they found
5. Be concise - this will be used as context for future analysis
