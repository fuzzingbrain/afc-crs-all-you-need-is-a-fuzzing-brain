# TaintSan for JavaScript

A taint tracking sanitizer for JavaScript/Node.js that detects injection vulnerabilities during fuzzing.

## Overview

TaintSan tracks "tainted" data from untrusted sources (user input, fuzzer data, files) and alerts when this data reaches dangerous "sinks" (eval, exec, SQL queries, file operations) without proper sanitization.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Data Flow with TaintSan                   │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│   SOURCES                    PROPAGATION                     │
│   ────────                   ───────────                     │
│   • Fuzzer input             • String concat (+)             │
│   • HTTP params              • Template literals             │
│   • File reads               • split/join/replace            │
│   • Environment vars         • toLowerCase/toUpperCase       │
│   • Database results         • trim/slice/substring          │
│                                                              │
│                         ↓                                    │
│                                                              │
│   SINKS (Detected)                                          │
│   ────────────────                                          │
│   • eval() / Function()     → Code Injection                │
│   • child_process.*         → Command Injection             │
│   • fs.readFile/writeFile   → Path Traversal                │
│   • http.request/fetch      → SSRF                          │
│   • SQL queries             → SQL Injection                 │
│   • __proto__ assignment    → Prototype Pollution           │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

## Quick Start

```javascript
const taintsan = require('./taintsan');

// Install monitors (do this BEFORE importing target code)
taintsan.install();

// Mark data as tainted
const userInput = taintsan.taint(req.body.name, taintsan.TaintSource.HTTP_REQUEST);

// Taint propagates through operations
const processed = userInput.toUpperCase().trim();
console.log(taintsan.isTainted(processed)); // true

// This would throw TaintViolationError:
eval(userInput);  // DETECTED!
```

## Integration with Jazzer.js

```javascript
const { fuzzWithTaint } = require('./jazzer_integration');

// Export fuzz target
module.exports.fuzz = fuzzWithTaint((data) => {
    // data is automatically tainted
    const str = data.toString();

    // Your code under test
    myParser.parse(str);
});
```

## Detected Vulnerability Classes

| Vulnerability | Sink Functions |
|--------------|----------------|
| **Code Injection** | `eval()`, `new Function()`, `setTimeout(string)` |
| **Command Injection** | `child_process.exec*`, `child_process.spawn` |
| **Path Traversal** | `fs.readFile`, `fs.writeFile`, `fs.unlink` |
| **SSRF** | `http.request`, `fetch`, `axios` |
| **SQL Injection** | `mysql.query`, `pg.query`, `sqlite.prepare` |
| **Prototype Pollution** | `Object.defineProperty`, `obj.__proto__` |

## API Reference

### Core Functions

```javascript
// Mark value as tainted
taintsan.taint(value, source)

// Check if value is tainted
taintsan.isTainted(value)

// Get taint metadata
taintsan.getTaintInfo(value)

// Tagged template for safe string building
taintsan.sql`SELECT * FROM users WHERE id = ${taintedId}`
```

### Configuration

```javascript
taintsan.config.throwOnSink = true;     // Throw on violation
taintsan.config.logViolations = true;   // Log to file
taintsan.config.monitorEval = true;     // Monitor eval()
taintsan.config.monitorChildProcess = true;
taintsan.config.monitorFileSystem = true;
taintsan.config.monitorNetwork = true;
taintsan.config.monitorSQL = true;
```

### Taint Sources

```javascript
taintsan.TaintSource.FUZZER        // Fuzzer-generated input
taintsan.TaintSource.HTTP_REQUEST  // HTTP request data
taintsan.TaintSource.FILE_INPUT    // File contents
taintsan.TaintSource.STDIN         // Standard input
taintsan.TaintSource.ENV_VAR       // Environment variables
taintsan.TaintSource.DATABASE      // Database results
taintsan.TaintSource.USER_MARKED   // Explicitly marked
```

## Example: Complete Fuzz Target

```javascript
// fuzz_target.js
const taintsan = require('./taintsan');
const { fuzzStringWithTaint } = require('./jazzer_integration');

// Install before importing target
taintsan.install();

const myApp = require('./my-vulnerable-app');

module.exports.fuzz = fuzzStringWithTaint((userInput) => {
    try {
        // Test various entry points
        myApp.processUserQuery(userInput);
        myApp.runCommand(userInput);
        myApp.readUserFile(userInput);
    } catch (e) {
        if (e instanceof taintsan.TaintViolationError) {
            // Found a vulnerability!
            throw e;
        }
        // Other errors are expected during fuzzing
    }
});
```

## Running the Demo

```bash
cd taintsan_javascript
node demo.js
```

## Limitations

1. **Primitive Strings**: JavaScript strings are immutable primitives. We use a `TaintedString` wrapper class, but some operations may unwrap it.

2. **JSON.parse**: Parsing JSON creates new string primitives that lose taint. Use `deepTaintObject()` to re-taint parsed objects.

3. **Native Code**: Operations in native code (C++ addons) bypass taint tracking.

4. **Performance**: Taint tracking adds overhead. Use only during testing/fuzzing.

## Future Enhancements

- [ ] Browser support (DOM sinks like innerHTML)
- [ ] React/Vue XSS detection
- [ ] WebSocket taint tracking
- [ ] Automatic HTTP request parameter tainting
- [ ] Integration with more SQL libraries
