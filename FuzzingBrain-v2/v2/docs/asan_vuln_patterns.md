# AddressSanitizer Detectable Vulnerability Patterns

Summary from AIxCC AFC Challenge Dataset.

## CWE Distribution (C/C++ Projects)

| CWE | Name | Count |
|-----|------|-------|
| CWE-122 | Heap-based Buffer Overflow | 5 |
| CWE-126 | Buffer Over-read | 5 |
| CWE-787 | Out-of-bounds Write | 3 |
| CWE-416 | Use After Free | 3 |
| CWE-121 | Stack-based Buffer Overflow | 3 |
| CWE-415 | Double Free | 2 |
| CWE-190 | Integer Overflow | 2 |
| CWE-125 | Out-of-bounds Read | 1 |
| CWE-680 | Integer Overflow to Buffer Overflow | 1 |

---

## Pattern 1: Integer Type Confusion (CWE-190, CWE-680)

**Root Cause**: Signed/unsigned type mismatch causes implicit integer promotion issues.

**Example** (FreeRDP):
```c
// VULNERABLE
INT8 channelCount;  // Signed, can be negative!

// FIXED
UINT8 channelCount; // Unsigned
```

**What to look for**:
- Signed types used for sizes, lengths, counts
- Type changes in struct members (especially in headers)
- Implicit conversions in comparisons

---

## Pattern 2: Double-Free (CWE-415)

**Root Cause**: Pointer not nullified after free, destructor called again.

**Example** (systemd):
```c
// VULNERABLE
static inline void freep(void *p) {
    free(*(void**) p);  // Not nullified!
}

// FIXED
static inline void freep(void *p) {
    *(void**)p = mfree(*(void**) p);  // Set to NULL
}
```

**What to look for**:
- Custom free wrappers
- Cleanup functions in destructors
- Missing NULL assignment after free

---

## Pattern 3: Use-After-Free from List Operations (CWE-416)

**Root Cause**: Element freed while still linked in a list.

**Example** (systemd):
```c
// VULNERABLE
LIST_FOREACH(conditions, c, head)
    if (type < 0 || c->type == type) {
        condition_free(c);  // Still in list!
    }

// FIXED
LIST_FOREACH(conditions, c, head)
    if (type < 0 || c->type == type) {
        LIST_REMOVE(conditions, head, c);  // Remove first
        condition_free(c);
    }
```

**What to look for**:
- List/tree traversal with deletion
- Missing unlink before free
- Dangling pointers in collections

---

## Pattern 4: Stack Buffer Overflow (CWE-121)

**Root Cause**: Fixed-size stack buffer, user-controlled copy length.

**Example** (Wireshark):
```c
// VULNERABLE
uint8_t buf[8] = { 0 };
// ... later ...
tvb_memcpy(tvb, buf, offset, data_len);  // data_len can be > 8!

// FIXED: Remove the vulnerable copy entirely
```

**What to look for**:
- Small fixed-size arrays on stack
- memcpy/strcpy with external length
- No bounds check before copy

---

## Pattern 5: Heap Overflow from Size Mismatch (CWE-122)

**Root Cause**: Allocation size differs from actual data size.

**Example** (libxml2):
```
Failure to correctly allocate sufficient data when handling
embedded entities leads to a heap-based buffer overflow.
```

**What to look for**:
- sizeof() on wrong variable (shadowing!)
- Type aliases with different sizes
- Calculation errors in allocation size

---

## Pattern 6: Counter Desync Leading to OOB (CWE-787)

**Root Cause**: Loop counter gets out of sync with actual position.

**Example** (systemd udev):
```c
// VULNERABLE: pos increments even on repeated prefixes
for (const char *k = str; *k != '"'; k++) {
    pos++;
    if (*k == 'e') is_escaped = true;
    // ...
}
// Later: memcpy uses pos which is wrong

// FIXED: Calculate offset from flags instead
str += is_escaped + is_case_insensitive + is_prefix_match;
```

**What to look for**:
- Manual position tracking in parsers
- Counters incremented unconditionally
- Offset calculations separate from actual position

---

## Pattern 7: Preprocessor Macro Abuse (CWE-122)

**Root Cause**: Macros used in unintended ways create hidden bugs.

**Example** (systemd catalog):
```c
// VULNERABLE: __COUNTER__ used as runtime value!
#define ILLEGAL_CAT_ENTRY atoi(TESTER)
#define TESTER TOSTRING(__COUNTER__)

if (payload[0] == ((ILLEGAL_CAT_ENTRY%10) + '0')){
    payload[ILLEGAL_CAT_ENTRY*100] = '\0';  // OOB write!
}
```

**What to look for**:
- Non-standard macro usage
- Macros that generate runtime values
- atoi/strtol on macro-generated strings

---

## Pattern 8: Type/Size Aliasing (observed in libpng)

**Root Cause**: Variable shadowing or typedef size differences.

**Example**:
```c
// VULNERABLE
char keyword[81];                        // 81 bytes
uInt max_keyword_wbytes = 41;
wpng_byte keyword[max_keyword_wbytes];   // Shadows! 41 * sizeof(wpng_byte)

read_length = sizeof(keyword);           // Gets wrong size!
```

**What to look for**:
- Same variable name in nested scopes
- typedef that might not be 1 byte (wchar, wide types)
- sizeof on potentially shadowed variables

---

## Summary: Key Patterns for SP Finding

1. **Type Issues**: signed/unsigned, typedef sizes, implicit conversions
2. **Memory Lifecycle**: free without NULL, UAF in collections
3. **Size Calculations**: sizeof mismatch, manual counters, allocation vs usage
4. **Buffer Operations**: fixed-size buffers + external lengths
5. **Macro/Preprocessor**: unusual macro patterns, compile-time vs runtime confusion
