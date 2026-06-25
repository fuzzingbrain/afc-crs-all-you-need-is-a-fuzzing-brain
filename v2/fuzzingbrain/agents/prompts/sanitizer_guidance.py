"""
Sanitizer-specific guidance templates for suspicious point agents.

These templates provide detailed vulnerability patterns that each sanitizer
can detect, helping agents focus on relevant bug types.
"""

ADDRESS_SANITIZER_GUIDANCE = """
### AddressSanitizer Detectable Bugs

**1. Type and Integer Issues** (Root cause of many bugs!)
- Signed types used for sizes, lengths, counts (can become negative!)
- Type changes in struct members between versions
- Implicit conversions in comparisons and arithmetic
- Integer overflow leading to small allocation then large write

**2. Size Calculation Errors** (CRITICAL - often missed!)
- sizeof() on wrong variable due to SHADOWING (same name in nested scope!)
- typedef sizes that differ from expected (wchar, wide_byte_t, custom types)
- Allocation size differs from actual data written
- sizeof(pointer) vs sizeof(*pointer) confusion

**3. Buffer Operations**
- Fixed-size stack/heap buffers with external length parameter
- memcpy/strcpy length from untrusted source without validation
- Array indexing with user-controlled or calculated index
- Off-by-one in loops, especially with null terminators

**4. Position/Counter Tracking**
- Manual position counters that diverge from actual offset
- Counters incremented unconditionally in conditional branches
- Offset calculations separate from pointer arithmetic

**5. Memory Lifecycle**
- Pointer not set to NULL after free (enables double-free)
- Element freed while still linked in list/tree (UAF on traversal)
- Custom free wrappers that don't nullify
- Destructor/cleanup called multiple times

**6. Macro and Preprocessor**
- Macros generating runtime values used as array indices
- Non-standard macro patterns that hide dangerous operations
- Compile-time vs runtime value confusion

### Variable Shadowing

When analyzing sizeof() or type operations, check if the same variable name
exists in an outer scope. Inner declarations shadow outer ones, causing sizeof()
to return the wrong size. This can be a root cause of buffer overflows.
"""

MEMORY_SANITIZER_GUIDANCE = """
### MemorySanitizer Detectable Bugs

**Uninitialized Memory Reads**
- Using variables before initialization
- Reading from uninitialized struct fields
- Uninitialized stack variables
- Partial struct initialization

**Information Leaks**
- Copying uninitialized data to output
- Using uninitialized values in conditions
- Passing uninitialized data to functions
"""

UNDEFINED_SANITIZER_GUIDANCE = """
### UndefinedBehaviorSanitizer Detectable Bugs

**Integer Overflow**
- Signed integer overflow/underflow
- Multiplication overflow
- Left shift overflow

**Null Pointer Dereference**
- Dereferencing NULL pointers
- Null member access

**Division/Shift Errors**
- Division by zero
- Modulo by zero
- Shift by negative amount
- Shift by >= type width
"""

GENERAL_SANITIZER_GUIDANCE = """
### General Vulnerability Patterns

- Buffer overflows and out-of-bounds access
- Memory corruption issues
- Integer handling errors
"""
