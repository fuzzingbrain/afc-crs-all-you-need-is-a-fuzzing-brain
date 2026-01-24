Compress tool results based on what the AGENT actually used.

## How to Decide What's Useful
Look at the AGENT's response after each tool result:
- If agent mentioned specific lines/functions → those are USEFUL
- If agent analyzed or reasoned about the result → keep that part
- If agent ignored the result or moved on → mark as [checked, not relevant]

## Task Context (for reference, DO NOT include in output)
{task_context}

## Additional Criteria
{compression_criteria}

## Messages to Compress
{messages_text}

## Output Format

Output ONLY compressed results. NO preamble.

For EACH tool call:

If agent USED it:
```
Tool: {tool_name}({key_args})
Signature: {function_signature}
Agent noted:
  - Line X: {code agent mentioned}
  - {agent's finding about this}
```

If agent IGNORED it:
```
Tool: {tool_name}({key_args})
[checked, not relevant]
```

## Rules
1. Keep what the AGENT referenced, not what YOU think is important
2. Preserve agent's exact reasoning and conclusions
3. For code: only lines the agent actually mentioned
4. Output compressed results directly - no summary, no preamble
