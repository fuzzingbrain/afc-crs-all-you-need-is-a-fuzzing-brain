Compress the conversation for a POV (Proof-of-Vulnerability) generation agent.

## Goal
Keep ONLY information that helps generate a crashing input. Remove everything else.

## Task Context (DO NOT include in output)
{task_context}

## What to Keep
{compression_criteria}

## Messages to Compress
{messages_text}

## Output Format

Output ONLY the compressed summary. NO preamble.

For tool calls the agent USED (referenced in its reasoning):
```
Tool: <tool_name>(<key_args>)
Finding: <what the agent learned from this>
```

For tool calls the agent IGNORED or that produced no useful info:
**Omit entirely. Do not mention them.**

For agent reasoning/conclusions:
```
Agent concluded: <key insight>
```

For POV attempts:
```
POV attempt #N: <generator approach> → <result: crashed/no crash/error> <why it failed if known>
```

## Rules
1. REMOVE all tool calls the agent didn't use - do NOT keep stubs
2. Keep data flow analysis: how input reaches the vulnerable function
3. Keep all POV attempt results and failure reasons
4. Keep constraint info: size limits, format requirements, magic bytes
5. Keep trace results: which functions were reached
6. Be aggressive - shorter is better
