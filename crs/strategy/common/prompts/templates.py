"""
Prompt Templates for CRS Strategies

All prompt templates are stored here for easy modification and maintenance.
Templates use Python f-string format for variable substitution.

Organization:
- Phase 0: Basic commit-based prompts
- Phase 1: CWE category-based prompts with sanitizer guidance
- Phase 2: Modified functions-based prompts
- Phase 3: Call path analysis prompts
"""

# ==================== Phase 0: Basic Commit-Based Prompts ====================

BASE_PROMPT = """You are a top software vulnerability detection expert, which helps to find vulnerabilities.
The provided commit introduces a vulnerability. Your job is to find the correct input to trigger the vulnerability.

Please output a Python script that creates five blob files (name as xi.bin with i=1..5). Each blob file will be run by this fuzzer code:
{fuzzer_code}

# Commit Diff
{commit_diff}
"""

# C/C++ specific guidance
C_LANGUAGE_SPECIFIC = """
IMPORTANT: Read the harness code carefully to understand how inputs are processed. In each xi.bin, you need to generate a complete blob that will trigger a sanitizer error.

Think through these steps:
1. What function contains the vulnerability? How do you reach this function?
2. What input will trigger the vulnerability?
3. Are there any other inputs required before reaching the target function?
4. How does the harness code process inputs? Follow the instructions in the harness.
5. Combine all this information to generate a complete blob.
{sanitizer_specific}
"""

# Java specific guidance
JAVA_LANGUAGE_SPECIFIC = """
IMPORTANT: Read the harness code carefully to understand how inputs are processed. In each xi.bin, you need to generate a complete blob that will trigger a Jazzer sanitizer error or Java exception.

Think through these steps:
1. What method contains the vulnerability? How do you reach this method?
2. What input will trigger the vulnerability?
3. Are there any other inputs required before reaching the target method?
4. How does the harness code process inputs? Follow the instructions in the harness.
5. Combine all this information to generate a complete blob.

The target project uses Jazzer sanitizers that can detect various types of vulnerabilities:
- ClojureLangHooks: detects vulnerabilities in Clojure code
- Deserialization: detects unsafe deserialization
- ExpressionLanguageInjection: detects expression language injection
- FilePathTraversal: detects path traversal vulnerabilities
- LdapInjection: detects LDAP injection
- NamingContextLookup: detects JNDI injection
- OsCommandInjection: detects OS command injection
- ReflectiveCall: detects unsafe reflection
- RegexInjection: detects regex injection
- RegexRoadblocks: detects regex denial of service
- ScriptEngineInjection: detects script engine injection
- ServerSideRequestForgery: detects SSRF vulnerabilities
- SQLInjection: detects SQL injection
- XPathInjection: detects XPath injection

Your goal is to trigger any of these sanitizer errors or a Java exception (like NullPointerException, ArrayIndexOutOfBoundsException, etc.) by crafting an input that exploits the vulnerability.
"""

# Common ending for all prompts
PROMPT_ENDING = """
Limit the blob size to 2MiB max

Your output must be a single Python script that creates five files named exactly x1.bin, x2.bin, x3.bin, x4.bin, and x5.bin. Each file should include a brief description of the targeted vulnerability and the function it affects. The vulnerability can be challenging to trigger, so diversify the contents of the .bin files to maximize the likelihood of success. It's acceptable if only one of the files successfully triggers the vulnerability.
"""

# ==================== Sanitizer-Specific Guidance ====================

SANITIZER_GUIDANCE_ADDRESS = """
The target project uses AddressSanitizer, which detects:
- Buffer overflows (stack, heap, global)
- Use-after-free errors
- Use-after-scope bugs
- Double-free errors

Your goal is to trigger an AddressSanitizer error by crafting an input that exploits the vulnerability.
"""

SANITIZER_GUIDANCE_MEMORY = """
The target project uses MemorySanitizer, which detects:
- Uninitialized memory reads
- Use of uninitialized values in conditional operations
- Passing uninitialized values to library functions

Your goal is to trigger a MemorySanitizer error by crafting an input that causes the program to use uninitialized memory.
"""

SANITIZER_GUIDANCE_UNDEFINED = """
The target project uses UndefinedBehaviorSanitizer, which detects:
- Integer overflow/underflow
- Signed integer overflow
- Division by zero
- Null pointer dereference
- Misaligned pointer dereference
- Unreachable code
- Invalid enum values
- Floating-point errors

Your goal is to trigger an UndefinedBehaviorSanitizer error by crafting an input that causes undefined behavior.
"""

SANITIZER_GUIDANCE_DEFAULT = """
The target project uses sanitizers that can detect various types of errors. Your goal is to trigger a sanitizer error by crafting an input that exploits the vulnerability.
"""

# ==================== Phase 1: CWE Category Descriptions ====================

CWE_DESCRIPTIONS_C = {
    "CWE-119": "Buffer Overflow - Writing or reading beyond buffer boundaries",
    "CWE-416": "Use After Free - Referencing memory after it has been freed",
    "CWE-476": "NULL Pointer Dereference - Dereferencing a null pointer",
    "CWE-190": "Integer Overflow - Arithmetic operations exceeding integer bounds",
    "CWE-122": "Heap-based Buffer Overflow - Overflow of heap-allocated memory",
    "CWE-787": "Out-of-bounds Write - Writing beyond array boundaries",
    "CWE-125": "Out-of-bounds Read - Reading beyond array boundaries",
    "CWE-134": "Format String - Uncontrolled format string vulnerabilities",
    "CWE-401": "Memory Leak - Failure to free allocated memory",
    "CWE-369": "Divide by Zero - Division or modulo by zero"
}

CWE_DESCRIPTIONS_JAVA = {
    "CWE-601": "Path Traversal - Improper restriction of file path traversal",
    "CWE-22": "Path Traversal - Improper limitation of a pathname to a restricted directory",
    "CWE-77": "Command Injection - Improper neutralization of special elements in commands",
    "CWE-78": "OS Command Injection - Improper neutralization of special elements in OS commands",
    "CWE-918": "Server-Side Request Forgery (SSRF) - Improper control of server-side requests",
    "CWE-79": "Cross-Site Scripting (XSS) - Injection of malicious scripts",
    "CWE-89": "SQL Injection - Manipulation of SQL queries",
    "CWE-200": "Information Exposure - Leakage of sensitive information",
    "CWE-306": "Missing Authentication - Lack of proper authentication",
    "CWE-502": "Deserialization - Unsafe deserialization of data",
    "CWE-611": "XXE Processing - XML External Entity vulnerabilities",
    "CWE-776": "Recursive Entity References - XML entity expansion",
    "CWE-400": "Resource Consumption - Denial of service through resource exhaustion",
    "CWE-755": "Exception Handling - Improper exception handling",
    "CWE-347": "Cryptographic Verification - Improper verification of signatures"
}

CATEGORY_PROMPT_C_BASE = """You are a top software vulnerability detection expert, which helps to find vulnerabilities, in particular, {category_desc} in C code.
The provided commit introduces a vulnerability. Your job is to find the correct input to trigger the vulnerability.

Please output a Python script that creates five blob files (name as xi.bin with i=1..5). Each blob file will be run by this fuzzer code:
{fuzzer_code}

# Commit Diff
{commit_diff}
"""

# Note: The detailed sanitizer+category combinations are handled in builder.py
# to keep this file focused on templates
