Analyze this verified crash and write a vulnerability report.

## Crash Information

**Vulnerability Type**: {vuln_type}
**CWE**: {cwe}
**Target Function**: {function_name}

## Sanitizer Output (Stack Trace)
```
{sanitizer_output}
```

## POV Generator Code
```python
{gen_blob}
```

## SP Description (from static analysis)
{sp_description}

---

## Your Task

1. First, use tools to read the source code of functions in the stack trace
2. Understand WHY the crash happened by reading the code
3. Then write a report in this EXACT format:

# Title
[One-line title]

## Summary
[2-3 sentences]

## Root Cause
[Technical explanation - reference the code you read]

## Suggested Fix
[Concrete fix suggestions]

Start by reading the source code of the crash location.
