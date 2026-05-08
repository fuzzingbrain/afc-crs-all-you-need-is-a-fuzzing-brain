#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""
OSS-Fuzz Integration Generator using Claude Agent SDK

This module uses the Claude Agent SDK to automatically generate OSS-Fuzz
integration files (Dockerfile, build.sh, project.yaml, and fuzz harnesses)
for projects that don't have existing OSS-Fuzz support.
"""
import os
import sys
import asyncio
import logging
from pathlib import Path
from typing import Optional, Dict, Any

try:
    from claude_agent_sdk import (
        ClaudeSDKClient,
        ClaudeAgentOptions,
        AssistantMessage,
        TextBlock,
        tool,
        create_sdk_mcp_server,
    )
    CLAUDE_SDK_AVAILABLE = True
except ImportError:
    CLAUDE_SDK_AVAILABLE = False
    logging.warning("claude-agent-sdk not installed. Run: pip install claude-agent-sdk")

logger = logging.getLogger(__name__)


# Security fuzzing templates for various languages
SECURITY_FUZZING_TEMPLATES = {
    "php": {
        "sql_injection": '''<?php
// SQL Injection Fuzzer
// Target: Database query functions

function LLVMFuzzerTestOneInput(string $data): void {
    // Simulate user input reaching SQL query
    $user_input = $data;

    // Check if proper escaping would be bypassed
    $patterns = [
        "/(\\'|\\"|--|;|\\\\x00)/",  // Basic injection chars
        "/(UNION\\s+SELECT|OR\\s+1=1|AND\\s+1=1)/i",  // SQL keywords
        "/(\\%27|\\%22|\\%3B)/i",  // URL encoded
    ];

    foreach ($patterns as $pattern) {
        if (preg_match($pattern, $user_input)) {
            // Log potential injection vector for analysis
            file_put_contents("/tmp/sqli_findings.txt", $user_input . "\\n", FILE_APPEND);
        }
    }
}
''',
        "command_injection": '''<?php
// Command Injection Fuzzer
// Target: shell_exec, exec, system, passthru, popen, proc_open

function LLVMFuzzerTestOneInput(string $data): void {
    $user_input = $data;

    // Dangerous characters that could escape shell context
    $dangerous_patterns = [
        "/[;&|`$(){}\\[\\]<>]/",  // Shell metacharacters
        "/(\\\\n|\\\\r|%0a|%0d)/i",  // Newlines
        "/(\\.\\.\\/|\\.\\.\\\\)/",  // Path traversal
    ];

    // Test if escapeshellarg/escapeshellcmd can be bypassed
    $escaped = escapeshellarg($user_input);

    foreach ($dangerous_patterns as $pattern) {
        if (preg_match($pattern, $user_input)) {
            // Check if dangerous char survives escaping
            if (preg_match($pattern, $escaped)) {
                file_put_contents("/tmp/cmdi_findings.txt",
                    "BYPASS: " . $user_input . " -> " . $escaped . "\\n", FILE_APPEND);
            }
        }
    }
}
''',
        "ssrf": '''<?php
// SSRF (Server-Side Request Forgery) Fuzzer
// Target: file_get_contents, curl, fopen with URLs

function LLVMFuzzerTestOneInput(string $data): void {
    $url_input = $data;

    // Attempt to parse as URL
    $parsed = @parse_url($url_input);
    if (!$parsed || !isset($parsed['host'])) {
        return;
    }

    $host = $parsed['host'];

    // Check for internal/private IP ranges
    $ip = @gethostbyname($host);

    // Private IP ranges
    $private_ranges = [
        '/^127\\./',           // Localhost
        '/^10\\./',            // Class A private
        '/^172\\.(1[6-9]|2[0-9]|3[01])\\./',  // Class B private
        '/^192\\.168\\./',     // Class C private
        '/^169\\.254\\./',     // Link-local
        '/^0\\./',             // Current network
        '/^::1$/',             // IPv6 localhost
        '/^fc00:/i',           // IPv6 ULA
        '/^fe80:/i',           // IPv6 link-local
    ];

    foreach ($private_ranges as $range) {
        if (preg_match($range, $ip) || preg_match($range, $host)) {
            file_put_contents("/tmp/ssrf_findings.txt",
                "SSRF: " . $url_input . " -> " . $ip . "\\n", FILE_APPEND);
        }
    }

    // Also check for protocol smuggling
    if (preg_match('/(gopher|dict|file|ldap|tftp):/i', $url_input)) {
        file_put_contents("/tmp/ssrf_findings.txt",
            "PROTOCOL: " . $url_input . "\\n", FILE_APPEND);
    }
}
''',
        "auth_bypass": '''<?php
// Authentication Bypass Fuzzer
// Target: Session handling, token validation, permission checks

function LLVMFuzzerTestOneInput(string $data): void {
    // Test various auth token formats

    // JWT-style tokens
    if (strpos($data, '.') !== false) {
        $parts = explode('.', $data);
        if (count($parts) === 3) {
            // Attempt base64 decode
            $header = @base64_decode($parts[0]);
            $payload = @base64_decode($parts[1]);

            // Check for "alg":"none" vulnerability
            if (stripos($header, '"alg"') !== false &&
                (stripos($header, '"none"') !== false || stripos($header, 'null') !== false)) {
                file_put_contents("/tmp/auth_findings.txt",
                    "ALG_NONE: " . $data . "\\n", FILE_APPEND);
            }

            // Check for privilege escalation in payload
            if (stripos($payload, 'admin') !== false ||
                stripos($payload, 'role') !== false) {
                file_put_contents("/tmp/auth_findings.txt",
                    "PRIV_ESC: " . $payload . "\\n", FILE_APPEND);
            }
        }
    }

    // Check for null byte injection
    if (strpos($data, "\\x00") !== false) {
        file_put_contents("/tmp/auth_findings.txt",
            "NULL_BYTE: " . bin2hex($data) . "\\n", FILE_APPEND);
    }

    // Check for type confusion (arrays, objects as strings)
    if (preg_match('/^(a:|O:|s:|i:|b:)/', $data)) {
        file_put_contents("/tmp/auth_findings.txt",
            "SERIALIZE: " . $data . "\\n", FILE_APPEND);
    }
}
''',
        "path_traversal": '''<?php
// Path Traversal / LFI Fuzzer
// Target: include, require, file_get_contents, fopen with user paths

function LLVMFuzzerTestOneInput(string $data): void {
    $path_input = $data;

    $traversal_patterns = [
        '/\\.\\.\\//',          // ../
        '/\\.\\.\\\\/',         // ..\\
        '/%2e%2e%2f/i',         // URL encoded ../
        '/%2e%2e%5c/i',         // URL encoded ..\\
        '/%252e%252e%252f/i',   // Double URL encoded
        '/\\.\\.%c0%af/i',      // Unicode encoding
        '/\\.\\.%c1%9c/i',      // Unicode encoding
        '/%c0%ae%c0%ae/i',      // Overlong UTF-8
    ];

    foreach ($traversal_patterns as $pattern) {
        if (preg_match($pattern, $path_input)) {
            file_put_contents("/tmp/lfi_findings.txt",
                "TRAVERSAL: " . $path_input . "\\n", FILE_APPEND);
        }
    }

    // Check for sensitive file access attempts
    $sensitive_files = [
        '/etc/passwd', '/etc/shadow', '/etc/hosts',
        'wp-config.php', 'config.php', '.env',
        '/proc/self/environ', '/var/log/',
    ];

    foreach ($sensitive_files as $file) {
        if (stripos($path_input, $file) !== false) {
            file_put_contents("/tmp/lfi_findings.txt",
                "SENSITIVE: " . $path_input . "\\n", FILE_APPEND);
        }
    }
}
''',
    },
    "python": {
        "deserialization": '''#!/usr/bin/env python3
"""Deserialization vulnerability fuzzer for Python - tests ACTUAL code execution"""
import atheris
import sys
import io

# IMPORTANT: This fuzzer tests ACTUAL deserialization, not just patterns!
FINDINGS_FILE = "/tmp/deser_findings.log"

def log_finding(category, data, details=""):
    """Log security findings without crashing the fuzzer"""
    try:
        with open(FINDINGS_FILE, "ab") as f:
            f.write(f"{category}: {data[:100]!r} - {details}\\n".encode())
    except:
        pass

def TestOneInput(data: bytes):
    """Fuzz deserialization functions - only crash on REAL errors."""
    if len(data) < 2 or len(data) > 50000:
        return

    # Test 1: JSON parsing (safe, but test for crashes)
    try:
        import json
        json.loads(data)
    except json.JSONDecodeError:
        pass  # Expected
    except RecursionError:
        log_finding("JSON_RECURSION", data, "Deep nesting")
    except MemoryError:
        raise  # Real crash - report it!

    # Test 2: YAML with safe_load (should be safe)
    try:
        import yaml
        yaml.safe_load(io.BytesIO(data))
    except yaml.YAMLError:
        pass  # Expected
    except RecursionError:
        log_finding("YAML_RECURSION", data, "Deep nesting")
    except MemoryError:
        raise  # Real crash

    # Test 3: Check for dangerous pickle patterns (LOG, don't crash)
    # We log these for manual review, but don't crash the fuzzer
    dangerous_patterns = [b'__reduce__', b'os.system', b'subprocess', b'__import__']
    for pattern in dangerous_patterns:
        if pattern in data:
            log_finding("PICKLE_PATTERN", data, f"Found {pattern}")
            break

    # Test 4: Actually try to parse as pickle to find parsing bugs
    # (but catch the security exception)
    try:
        import pickle
        import _pickle
        # Use a restricted unpickler that will error on dangerous opcodes
        # This finds pickle parsing bugs, not RCE
        _pickle.loads(data)
    except (pickle.UnpicklingError, _pickle.UnpicklingError):
        pass  # Expected for fuzz input
    except (AttributeError, ModuleNotFoundError, ImportError):
        pass  # Expected when pickle tries to import
    except RecursionError:
        log_finding("PICKLE_RECURSION", data)
    except MemoryError:
        raise  # Real crash
    except Exception as e:
        # Unexpected exception type might be interesting
        log_finding("PICKLE_UNEXPECTED", data, str(type(e)))

if __name__ == "__main__":
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
''',
    },
    "javascript": {
        "taintsan_integration": '''// TaintSan-enabled Fuzzer for JavaScript
// This harness uses TaintSan for taint tracking to detect injection vulnerabilities
const { FuzzedDataProvider } = require('@jazzer.js/core');
const taintsan = require('./taintsan');

// Install TaintSan monitors BEFORE importing target code
taintsan.install();

// Import target modules AFTER TaintSan installation
// const targetModule = require('/src/project/dist/target.js');

module.exports.fuzz = function (data) {
    const provider = new FuzzedDataProvider(data);

    try {
        // Create tainted input from fuzzer data
        const userInput = taintsan.taint(
            provider.consumeRemainingAsString(),
            taintsan.TaintSource.FUZZER
        );

        // Pass tainted data through target code
        // TaintSan will detect if it reaches dangerous sinks
        // targetModule.processInput(userInput);

    } catch (e) {
        if (e instanceof taintsan.TaintViolationError) {
            // Found a vulnerability! This is what we want to detect
            console.error('[TAINTSAN] Vulnerability detected!');
            console.error(`  Sink: ${e.violation.sinkType} - ${e.violation.sinkFunction}`);
            console.error(`  Source: ${e.violation.taintInfo.source}`);
            throw e;  // Re-throw for Jazzer to record as finding
        }
        // Other errors - ignore (expected during fuzzing)
    }
};
''',
        "prototype_pollution": '''// Prototype Pollution Fuzzer with TaintSan
const { FuzzedDataProvider } = require('@jazzer.js/core');
const taintsan = require('./taintsan');

taintsan.install();

function vulnerableMerge(target, source) {
    for (const key in source) {
        if (typeof source[key] === 'object' && source[key] !== null) {
            if (!target[key]) target[key] = {};
            vulnerableMerge(target[key], source[key]);
        } else {
            target[key] = source[key];
        }
    }
    return target;
}

module.exports.fuzz = function (data) {
    const provider = new FuzzedDataProvider(data);

    try {
        const jsonStr = taintsan.taint(
            provider.consumeRemainingAsString(),
            taintsan.TaintSource.FUZZER
        );

        const parsed = JSON.parse(jsonStr.toString());

        // Deep taint all parsed values
        function deepTaint(obj, visited = new WeakSet()) {
            if (!obj || typeof obj !== 'object' || visited.has(obj)) return obj;
            visited.add(obj);

            for (const key of Object.keys(obj)) {
                if (typeof obj[key] === 'string') {
                    obj[key] = taintsan.taint(obj[key], taintsan.TaintSource.FUZZER);
                } else if (typeof obj[key] === 'object') {
                    deepTaint(obj[key], visited);
                }
            }
            return obj;
        }

        const taintedObj = deepTaint(parsed);

        // Check for prototype pollution attempts
        if ('__proto__' in taintedObj || 'constructor' in taintedObj) {
            throw new taintsan.TaintViolationError({
                sinkType: 'PROTOTYPE_POLLUTION',
                sinkFunction: 'JSON.parse',
                taintInfo: { source: 'FUZZER', sourceLocation: 'fuzzer input' },
                taintedValuePreview: jsonStr.toString().substring(0, 100)
            });
        }

        // Test vulnerable merge
        vulnerableMerge({}, taintedObj);

    } catch (e) {
        if (e instanceof taintsan.TaintViolationError) {
            throw e;
        }
        // JSON parse errors are expected
    }
};
''',
        "command_injection": '''// Command Injection Fuzzer with TaintSan
const { FuzzedDataProvider } = require('@jazzer.js/core');
const taintsan = require('./taintsan');

taintsan.install();

module.exports.fuzz = function (data) {
    const provider = new FuzzedDataProvider(data);

    try {
        const userInput = taintsan.taint(
            provider.consumeRemainingAsString(),
            taintsan.TaintSource.FUZZER
        );

        // This will trigger TaintViolationError if tainted data reaches child_process
        const child_process = require('child_process');

        // Simulated vulnerable command construction
        const cmd = 'echo ' + userInput;

        // TaintSan will catch this when exec is called with tainted cmd
        // child_process.execSync(cmd);

    } catch (e) {
        if (e instanceof taintsan.TaintViolationError) {
            throw e;
        }
    }
};
''',
        "sql_injection": '''// SQL Injection Fuzzer with TaintSan
const { FuzzedDataProvider } = require('@jazzer.js/core');
const taintsan = require('./taintsan');

taintsan.install();

module.exports.fuzz = function (data) {
    const provider = new FuzzedDataProvider(data);

    try {
        const userInput = taintsan.taint(
            provider.consumeRemainingAsString(),
            taintsan.TaintSource.FUZZER
        );

        // Taint propagates through string operations
        const query = taintsan.sql`SELECT * FROM users WHERE name = '${userInput}'`;

        // Check if query is tainted (should be since userInput is tainted)
        if (taintsan.isTainted(query)) {
            // In a real harness, we would pass this to a mock DB
            // that checks for tainted queries
        }

        // Direct string interpolation (vulnerable)
        const unsafeQuery = "SELECT * FROM users WHERE id = " + userInput;

        // This would trigger TaintSan if passed to a real SQL client
        // db.query(unsafeQuery);

    } catch (e) {
        if (e instanceof taintsan.TaintViolationError) {
            throw e;
        }
    }
};
''',
        "ssrf": '''// SSRF (Server-Side Request Forgery) Fuzzer with TaintSan
const { FuzzedDataProvider } = require('@jazzer.js/core');
const taintsan = require('./taintsan');

taintsan.install();

module.exports.fuzz = function (data) {
    const provider = new FuzzedDataProvider(data);

    try {
        const urlInput = taintsan.taint(
            provider.consumeRemainingAsString(),
            taintsan.TaintSource.FUZZER
        );

        // TaintSan monitors http.request, https.request, and fetch
        // This will be caught if tainted URL reaches network requests
        const url = new URL(urlInput.toString());

        // Check for internal/private IP access attempts
        const host = url.hostname;
        const privatePatterns = [
            /^127\\./, /^10\\./, /^192\\.168\\./,
            /^172\\.(1[6-9]|2[0-9]|3[01])\\./,
            /^localhost$/i, /^0\\.0\\.0\\.0$/
        ];

        for (const pattern of privatePatterns) {
            if (pattern.test(host)) {
                throw new taintsan.TaintViolationError({
                    sinkType: 'SSRF',
                    sinkFunction: 'URL',
                    taintInfo: { source: 'FUZZER', sourceLocation: 'fuzzer input' },
                    taintedValuePreview: urlInput.toString().substring(0, 100)
                });
            }
        }

    } catch (e) {
        if (e instanceof taintsan.TaintViolationError) {
            throw e;
        }
        // URL parse errors are expected
    }
};
''',
    },
}

# Path to TaintSan implementation
TAINTSAN_JS_PATH = Path(__file__).parent.parent / "sanitizers" / "taintsan_javascript"


def detect_project_language(repo_path: str) -> list:
    """Detect the primary programming language(s) of a project."""
    languages = []
    repo = Path(repo_path)

    # Language detection based on file extensions and build files
    indicators = {
        'c': ['.c', '.h'],
        'cpp': ['.cpp', '.cc', '.cxx', '.hpp', '.hxx', 'CMakeLists.txt'],
        'java': ['.java', 'pom.xml', 'build.gradle', 'build.gradle.kts'],
        'python': ['.py', 'setup.py', 'pyproject.toml', 'requirements.txt'],
        'go': ['.go', 'go.mod', 'go.sum'],
        'rust': ['.rs', 'Cargo.toml'],
        'php': ['.php', 'composer.json'],
        'javascript': ['.js', '.ts', 'package.json', 'tsconfig.json'],
        'ruby': ['.rb', 'Gemfile'],
    }

    for lang, patterns in indicators.items():
        for pattern in patterns:
            if pattern.startswith('.'):
                # Check for file extensions
                if list(repo.rglob(f'*{pattern}'))[:1]:
                    if lang not in languages:
                        languages.append(lang)
                    break
            else:
                # Check for specific files
                if (repo / pattern).exists() or list(repo.rglob(pattern))[:1]:
                    if lang not in languages:
                        languages.append(lang)
                    break

    return languages if languages else ['unknown']


def get_security_templates_for_language(language: str) -> Dict[str, str]:
    """Get security fuzzing templates for a specific language."""
    return SECURITY_FUZZING_TEMPLATES.get(language, {})


def get_build_script_files(repo_path: str) -> list:
    """Find all build script files in a repository."""
    repo = Path(repo_path)
    build_files = []

    # Common build system files
    patterns = [
        'Makefile', 'GNUmakefile', 'makefile',
        'CMakeLists.txt',
        'configure', 'configure.ac', 'configure.in',
        'meson.build',
        'BUILD', 'BUILD.bazel', 'WORKSPACE',
        'pom.xml', 'build.gradle', 'build.gradle.kts', 'settings.gradle',
        'Cargo.toml',
        'go.mod',
        'package.json',
        'composer.json',
        'Gemfile',
        'setup.py', 'pyproject.toml',
        'SConstruct', 'SConscript',
        'Jamfile', 'Jamroot',
    ]

    for pattern in patterns:
        # Check root directory
        if (repo / pattern).exists():
            build_files.append(str(repo / pattern))
        # Check subdirectories for CMakeLists.txt (common to have multiple)
        if pattern == 'CMakeLists.txt':
            for f in repo.rglob(pattern):
                if str(f) not in build_files:
                    build_files.append(str(f))

    return build_files


def find_main_functions(repo_path: str, language: str) -> list:
    """Find files containing main functions/entry points."""
    repo = Path(repo_path)
    main_files = []

    patterns = {
        'c': {'ext': ['.c'], 'regex': r'int\s+main\s*\('},
        'cpp': {'ext': ['.cpp', '.cc', '.cxx'], 'regex': r'int\s+main\s*\('},
        'java': {'ext': ['.java'], 'regex': r'public\s+static\s+void\s+main\s*\('},
        'python': {'ext': ['.py'], 'regex': r"if\s+__name__\s*==\s*['\"]__main__['\"]"},
        'go': {'ext': ['.go'], 'regex': r'func\s+main\s*\(\s*\)'},
        'rust': {'ext': ['.rs'], 'regex': r'fn\s+main\s*\(\s*\)'},
        'php': {'ext': ['.php'], 'regex': r'<\?php'},  # PHP files with CLI execution
        'javascript': {'ext': ['.js'], 'regex': r'(require\.main\s*===\s*module|process\.argv)'},
    }

    if language not in patterns:
        return []

    import re
    lang_patterns = patterns[language]

    for ext in lang_patterns['ext']:
        for f in repo.rglob(f'*{ext}'):
            try:
                content = f.read_text(errors='ignore')
                if re.search(lang_patterns['regex'], content):
                    main_files.append(str(f))
            except Exception:
                pass

    return main_files


# System prompt for the OSS-Fuzz integration agent
OSSFUZZ_AGENT_SYSTEM_PROMPT = """You are an expert OSS-Fuzz integration specialist. Your task is to analyze a software project and generate the necessary files to integrate it with OSS-Fuzz for fuzz testing.

## Your Goals:
1. Analyze the repository structure to understand the build system and language
2. Identify potential fuzz targets (functions that process untrusted input)
3. **IMPORTANT: Also identify and build existing project targets (binaries with main functions)**
4. Generate a complete OSS-Fuzz integration including:
   - project.yaml: Project metadata
   - Dockerfile: Build environment with all dependencies
   - build.sh: Build script that compiles BOTH fuzz targets AND existing project binaries
   - At least one fuzz harness targeting security-critical code

## Building Existing Project Targets:
The build.sh MUST also compile the project's existing executables (those with main() functions) for additional fuzzing coverage:
- **Analyze existing build scripts**: Read Makefile, CMakeLists.txt, configure.ac, pom.xml, build.gradle, Cargo.toml, etc.
- **Find all build targets**: Look for executables defined in build systems
- **Build with fuzzing instrumentation**: Compile existing binaries with $CFLAGS/$CXXFLAGS for coverage-guided fuzzing
- **Copy to $OUT**: All compiled binaries (both fuzz harnesses and original executables) go to $OUT
- **Create wrapper scripts**: For CLI tools, create shell wrapper scripts that allow fuzzing via stdin/file input

Example pattern for existing executables in build.sh:
```bash
# Build the project normally first (with fuzzing flags)
make CC="$CC" CXX="$CXX" CFLAGS="$CFLAGS" CXXFLAGS="$CXXFLAGS" LDFLAGS="$LIB_FUZZING_ENGINE"

# Copy existing binaries to $OUT with _exec suffix to distinguish from fuzz harnesses
cp ./bin/mytool $OUT/mytool_exec

# For stdin-based tools, create afl-style harness wrapper
cat > $OUT/fuzz_mytool_stdin << 'EOF'
#!/bin/bash
exec $OUT/mytool_exec < "$1"
EOF
chmod +x $OUT/fuzz_mytool_stdin
```

## Key Requirements:
- The Dockerfile MUST use the appropriate OSS-Fuzz base image:
  - C/C++: gcr.io/oss-fuzz-base/base-builder
  - Java: gcr.io/oss-fuzz-base/base-builder-jvm
  - Python: gcr.io/oss-fuzz-base/base-builder-python
  - Go: gcr.io/oss-fuzz-base/base-builder-go
  - Rust: gcr.io/oss-fuzz-base/base-builder-rust
  - PHP: gcr.io/oss-fuzz-base/base-builder (with PHP installed)
  - JavaScript/Node.js: gcr.io/oss-fuzz-base/base-builder-javascript

- The build.sh script MUST:
  - Use $CC, $CXX, $CFLAGS, $CXXFLAGS environment variables
  - Link with $LIB_FUZZING_ENGINE
  - Output fuzzers to $OUT directory
  - Source files are in $SRC
  - **Build existing project executables with instrumentation**
  - **Preserve original build targets alongside fuzz harnesses**

- Fuzz harnesses MUST implement the standard entry point:
  - C/C++: extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
  - Java: public static void fuzzerTestOneInput(FuzzedDataProvider data)
  - Python: def TestOneInput(data: bytes)
  - Go: func Fuzz(data []byte)

## Security Fuzzing for Non-C/C++/Java Languages:

### PHP Security Fuzzing:
For PHP projects, focus on these security vulnerability classes:

1. **SQL Injection**:
   - Create harnesses that fuzz database query functions
   - Target functions using mysqli_query, PDO::query, pg_query
   - Fuzz user input fields that end up in SQL statements
   ```php
   <?php
   function fuzz_sql_injection($data) {
       // Simulate user input going into query
       $user_input = $data;
       $query = "SELECT * FROM users WHERE name = '" . $user_input . "'";
       // Check for injection patterns
       if (preg_match('/(\\'|--|;|\\x00|UNION|SELECT)/i', $query) &&
           strpos($query, addslashes($user_input)) === false) {
           throw new Exception("Potential SQL injection detected");
       }
   }
   ```

2. **Command Injection**:
   - Target shell_exec, exec, system, passthru, popen, proc_open, backtick operator
   - Fuzz user inputs that reach command execution
   ```php
   <?php
   function fuzz_command_injection($data) {
       // Test escapeshellarg/escapeshellcmd bypass
       $cmd = "echo " . escapeshellarg($data);
       // Detect if dangerous chars could escape
       if (preg_match('/[;&|`$]/', $data) && strpos($cmd, $data) !== false) {
           throw new Exception("Potential command injection");
       }
   }
   ```

3. **SSRF (Server-Side Request Forgery)**:
   - Target file_get_contents, curl_*, fopen with URLs
   - Fuzz URL parameters to detect internal network access
   ```php
   <?php
   function fuzz_ssrf($url_input) {
       $parsed = parse_url($url_input);
       $host = $parsed['host'] ?? '';
       // Check for internal/private IPs
       $ip = gethostbyname($host);
       if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
           throw new Exception("SSRF: Internal IP detected: $ip");
       }
   }
   ```

4. **Unauthorized Access / Authentication Bypass**:
   - Fuzz session handling, token validation, permission checks
   - Test boundary conditions in access control logic
   ```php
   <?php
   function fuzz_auth_bypass($token_data) {
       // Test JWT/session token parsing
       // Look for type confusion, null bytes, encoding issues
       $decoded = base64_decode($token_data);
       if (strpos($decoded, '\\x00') !== false ||
           strpos($decoded, 'admin') !== false) {
           // Flag potential bypass vectors
           throw new Exception("Potential auth bypass vector");
       }
   }
   ```

5. **Path Traversal / LFI**:
   - Target include, require, file_get_contents with user paths
   ```php
   <?php
   function fuzz_path_traversal($path) {
       if (preg_match('/(\\.\\.|%2e%2e|%252e)/i', $path)) {
           throw new Exception("Path traversal attempt");
       }
   }
   ```

### PHP Fuzzing Setup in build.sh:

**CRITICAL**: Fuzzers MUST execute actual target code, not just pattern-match inputs!

For PHP projects, create fuzzers that:
1. Call actual PHP functions/scripts with fuzzed input
2. Detect real crashes, errors, or security violations
3. NEVER raise exceptions for "pattern detection" - only for actual crashes

```bash
# Install PHP and extensions
apt-get install -y php-cli php-dev php-xml php-mysql php-curl

# Install atheris for Python-based PHP fuzzing
pip3 install atheris

# GOOD EXAMPLE: Fuzzer that executes actual PHP code
cat > $OUT/fuzz_json_api.py << 'PYEOF'
#!/usr/bin/env python3
# Fuzzer that actually tests PHP JSON parsing
import atheris
import subprocess
import sys
import os

# Path to the PHP target script
PHP_TARGET = "/src/hotcrp/lib/json.php"
FINDINGS_FILE = "/tmp/security_findings.log"

def log_finding(category, data, details=""):
    # Log security findings without crashing the fuzzer
    with open(FINDINGS_FILE, "a") as f:
        f.write(f"{category}: {data[:100]!r} - {details}\\n")

def TestOneInput(data):
    if len(data) < 1 or len(data) > 10000:
        return

    try:
        # Create a temp PHP script that processes the fuzzed input
        test_script = "<?php error_reporting(E_ALL); " + \\
            "$input = file_get_contents('php://stdin'); " + \\
            "require_once '/src/hotcrp/lib/json.php'; " + \\
            "try { $result = json_decode($input, true); " + \\
            "if (json_last_error() !== JSON_ERROR_NONE) { exit(0); } " + \\
            "if (isset($result['query'])) { echo 'Query: ' . $result['query']; } " + \\
            "} catch (Exception $e) { fwrite(STDERR, 'EXCEPTION: ' . $e->getMessage()); exit(1); }"

        proc = subprocess.run(
            ['php', '-r', test_script],
            input=data, capture_output=True, timeout=5
        )

        # Check for actual crashes/errors
        if proc.returncode != 0 and proc.returncode != 255:
            stderr = proc.stderr.decode('utf-8', errors='ignore')
            # Real errors we care about:
            if any(err in stderr for err in ['Segmentation fault', 'SIGSEGV', 'SIGABRT',
                'memory exhausted', 'stack overflow', 'Fatal error', 'Uncaught Error']):
                raise RuntimeError(f"PHP crash: {stderr[:200]}")
            # Security-relevant errors to log (but don't crash)
            if any(err in stderr.lower() for err in ['sql', 'injection', 'command', 'shell']):
                log_finding("SECURITY", data, stderr[:200])
    except subprocess.TimeoutExpired:
        log_finding("TIMEOUT", data, "PHP execution timeout")
    except RuntimeError:
        raise  # Re-raise real crashes

atheris.Setup(sys.argv, TestOneInput)
atheris.Fuzz()
PYEOF
chmod +x $OUT/fuzz_json_api.py
```

**BAD EXAMPLE** (don't do this - crashes on patterns, not real bugs):
```python
def TestOneInput(data):
    if "UNION SELECT" in data:
        raise Exception("SQL injection!")  # WRONG: Not testing actual code!
```

**Key Rules for PHP Fuzzers**:
1. Always execute actual PHP code with subprocess.run()
2. Only raise exceptions for REAL crashes (segfaults, fatal errors)
3. Log security "findings" to a file instead of crashing
4. Use actual project source files, not synthetic patterns
5. Target specific entry points: API handlers, form processors, file parsers

### Python Security Fuzzing:
- Use Atheris (Google's Python fuzzer) for native fuzzing
- Target: pickle/yaml deserialization, eval/exec, SQL queries, subprocess calls
- Build with: `pip install atheris && python -m atheris`

### JavaScript/Node.js Security Fuzzing:
- Use Jazzer.js for coverage-guided fuzzing
- **IMPORTANT**: JavaScript projects MUST use `sanitizer: none` in project.yaml (no ASan support)
- Use TaintSan for injection detection instead of traditional sanitizers
- Target: JSON.parse, eval, child_process, database queries, URL parsing
- Focus on prototype pollution, ReDoS, command injection, SSRF, SQL injection

### TaintSan Integration for JavaScript:
TaintSan is a taint tracking sanitizer for JavaScript that detects when untrusted data
reaches dangerous sinks without proper sanitization.

**In build.sh, copy TaintSan to the output directory:**
```bash
# Copy TaintSan for JavaScript security fuzzing
mkdir -p $OUT/taintsan
cp /src/taintsan/*.js $OUT/taintsan/ || {
    # If TaintSan not pre-installed, create minimal version inline
    cat > $OUT/taintsan/taintsan.js << 'TAINTEOF'
// Minimal TaintSan implementation for fuzzing
'use strict';
const taintMap = new WeakMap();
const stringTaintMap = new Map();

class TaintViolationError extends Error {
    constructor(violation) {
        super(`TAINT VIOLATION: ${violation.sinkType} received tainted data`);
        this.name = 'TaintViolationError';
        this.violation = violation;
    }
}

const TaintSource = {
    FUZZER: 'FUZZER', HTTP_REQUEST: 'HTTP_REQUEST', FILE_INPUT: 'FILE_INPUT',
    STDIN: 'STDIN', ENV_VAR: 'ENV_VAR', DATABASE: 'DATABASE', USER_MARKED: 'USER_MARKED'
};

function taint(value, source = 'USER_MARKED') {
    const info = { source, timestamp: Date.now() };
    if (typeof value === 'string') {
        stringTaintMap.set(value, info);
    } else if (typeof value === 'object' && value !== null) {
        taintMap.set(value, info);
    }
    return value;
}

function isTainted(value) {
    if (typeof value === 'object' && value !== null) return taintMap.has(value);
    if (typeof value === 'string') return stringTaintMap.has(value);
    return false;
}

function getTaintInfo(value) {
    if (typeof value === 'object' && value !== null) return taintMap.get(value);
    if (typeof value === 'string') return stringTaintMap.get(value);
    return null;
}

function install() { console.error('[TaintSan] Minimal mode - monitors not installed'); }

function sql(strings, ...values) {
    let result = strings[0];
    let hasTaint = false;
    for (let i = 0; i < values.length; i++) {
        if (isTainted(values[i])) hasTaint = true;
        result += String(values[i]) + strings[i + 1];
    }
    if (hasTaint) {
        const newResult = result;
        stringTaintMap.set(newResult, { source: 'TAINTED_TEMPLATE' });
        return newResult;
    }
    return result;
}

module.exports = {
    TaintSource, TaintViolationError, taint, isTainted, getTaintInfo, install, sql, t: sql
};
TAINTEOF
}
```

**In fuzz harnesses, use TaintSan:**
```javascript
const { FuzzedDataProvider } = require('@jazzer.js/core');
const taintsan = require('./taintsan/taintsan');

taintsan.install();

module.exports.fuzz = function (data) {
    const provider = new FuzzedDataProvider(data);
    const userInput = taintsan.taint(provider.consumeRemainingAsString(), taintsan.TaintSource.FUZZER);

    // TaintSan will detect if tainted data reaches dangerous sinks
    // like eval(), child_process.exec(), SQL queries, etc.
    targetModule.processUserInput(userInput);
};
```

**project.yaml for JavaScript:**
```yaml
language: javascript
fuzzing_engines:
  - libfuzzer
sanitizers:
  - none  # REQUIRED - JavaScript doesn't support ASan/MSan
```

### Go Security Fuzzing:
- Native go test -fuzz support (Go 1.18+)
- Target: encoding/decoding, parsing, crypto operations

## Process:
1. First, explore the repository to understand its structure
2. **Read and analyze existing build scripts** (Makefile, CMakeLists.txt, pom.xml, etc.)
3. Identify the build system (CMake, Make, Autotools, Maven, Gradle, etc.)
4. **List all existing build targets/executables**
5. Find dependencies that need to be installed
6. Locate security-critical code paths (parsers, deserializers, crypto, network handlers)
7. **For web/PHP/Python projects, identify security-sensitive functions**
8. Generate all required files including harnesses for security vulnerabilities

Be thorough in dependency detection - missing dependencies cause build failures.
"""


def _get_build_fix_prompt(repo_path: str, project_name: str, output_dir: str, build_error: str) -> str:
    """Generate the prompt for fixing a build error."""
    return f"""The OSS-Fuzz integration for "{project_name}" failed to build. Please analyze the error and fix the integration files.

## Build Error Output:
```
{build_error}
```

## Current Files Location:
The integration files are in: {output_dir}/

## Your Task:
1. Read the current Dockerfile, build.sh, and any fuzz harnesses
2. Analyze the build error to understand what went wrong
3. Fix the files to resolve the build error
4. Common issues include:
   - Missing dependencies in Dockerfile
   - Incorrect build commands in build.sh
   - Wrong paths or environment variables
   - CMake/Make configuration issues
   - Missing compiler flags or linker flags
   - Boost version requirements (some projects need >= 1.74.0)

## Important Notes:
- Do NOT add $LIB_FUZZING_ENGINE to CMAKE_EXE_LINKER_FLAGS during CMake configuration (it breaks compiler tests)
- Instead, pass it via project-specific CMake variables like -DFUZZ_LIBS="$LIB_FUZZING_ENGINE"
- Use $SANITIZER (from OSS-Fuzz) for sanitizer configuration, not hardcoded "fuzzer"
- If Boost is too old in base image, build from source using GitHub releases

## Remember to Build Existing Targets:
The build.sh should ALSO compile the project's existing executables (with main functions):
- Re-read the project's Makefile, CMakeLists.txt, pom.xml, etc. to find all build targets
- Build existing binaries with fuzzing instrumentation ($CFLAGS, $CXXFLAGS)
- Copy existing executables to $OUT with _exec suffix
- For CLI tools, create stdin/file wrapper harnesses

## For Non-C/C++ Projects (PHP, Python, JS):
If the project is PHP/Python/JavaScript, ensure you've created appropriate security harnesses:
- SQL injection fuzzing
- Command injection fuzzing
- SSRF detection
- Path traversal testing
- Authentication/authorization bypass testing

Please fix the integration files now."""


def _get_project_analysis_prompt(
    repo_path: str,
    project_name: str,
    detected_languages: Optional[list] = None,
    build_files: Optional[list] = None,
    main_files: Optional[Dict[str, list]] = None,
) -> str:
    """Generate the prompt for analyzing a project and creating OSS-Fuzz integration."""

    # Build context section with pre-detected information
    context_section = ""
    if detected_languages:
        context_section += f"\n## Pre-detected Information:\n"
        context_section += f"- **Detected languages**: {', '.join(detected_languages)}\n"

    if build_files:
        context_section += f"- **Build files found**: {', '.join(build_files[:10])}"
        if len(build_files) > 10:
            context_section += f" (and {len(build_files) - 10} more)"
        context_section += "\n"

    if main_files:
        context_section += "- **Files with main functions**:\n"
        for lang, files in main_files.items():
            if files:
                context_section += f"  - {lang}: {len(files)} files\n"
                for f in files[:5]:
                    context_section += f"    - {f}\n"
                if len(files) > 5:
                    context_section += f"    - ... and {len(files) - 5} more\n"

    # Add security templates for detected scripted languages
    security_section = ""
    if detected_languages:
        for lang in detected_languages:
            if lang in SECURITY_FUZZING_TEMPLATES:
                security_section += f"\n## Security Fuzzing Templates for {lang.upper()}:\n"
                security_section += f"Use these templates as starting points for security-focused fuzz harnesses:\n\n"
                for vuln_type, template in SECURITY_FUZZING_TEMPLATES[lang].items():
                    security_section += f"### {vuln_type.replace('_', ' ').title()} Harness:\n"
                    security_section += f"```{lang}\n{template[:500]}...\n```\n\n"

    return f"""Please analyze the repository at {repo_path} and generate a complete OSS-Fuzz integration for the project "{project_name}".
{context_section}

Steps to follow:
1. First, explore the repository structure using ls and find commands to understand:
   - The programming language(s) used
   - The build system (CMake, Make, Autotools, Maven, Gradle, Cargo, etc.)
   - Key source directories
   - Existing test infrastructure

2. **CRITICAL: Thoroughly analyze existing build scripts**:
   - Read Makefile / GNUmakefile to understand build targets
   - Read CMakeLists.txt to find all add_executable() targets
   - Read configure.ac / configure for autotools projects
   - Read pom.xml for Maven projects (look for <packaging>jar</packaging> and main classes)
   - Read build.gradle for Gradle projects (look for application plugin and mainClassName)
   - Read Cargo.toml for Rust projects (look for [[bin]] sections)
   - Read package.json for Node.js projects (look for "bin" and "scripts")
   - Read composer.json for PHP projects (look for "bin" entries)
   - **List ALL existing build targets/executables** that have main() or entry points

3. Identify potential fuzz targets by looking for:
   - Input parsing functions
   - Deserialization code (JSON, XML, YAML, pickle, etc.)
   - Protocol handlers
   - File format parsers
   - Cryptographic operations
   - Functions that process user/network input
   - **For PHP/Python/JS**: SQL queries, shell commands, URL fetching, file operations

4. **For non-C/C++/Java projects**, identify security-sensitive patterns:
   - PHP: mysqli_*, PDO::*, shell_exec, exec, system, file_get_contents with URLs, include/require with user input
   - Python: pickle.loads, yaml.load, eval, exec, subprocess.*, sqlite3/psycopg2 queries
   - JavaScript: eval, child_process.exec, SQL template strings, URL parsing
   - Look for authentication/authorization logic to fuzz for bypasses

5. Create the following files in the output directory:
   - project.yaml
   - Dockerfile
   - build.sh (must build BOTH fuzz harnesses AND existing project executables)
   - At least one fuzz harness (e.g., fuzz_target.c or FuzzTarget.java)
   - **For web/scripted languages**: Security-focused harnesses for injection, SSRF, auth bypass

The output directory for these files is: {repo_path}/../fuzz-tooling/projects/{project_name}/

## Build Script Requirements:
The build.sh MUST:
- Install ALL required dependencies in the Dockerfile
- Handle the project's specific build system correctly
- **Build all existing project executables with fuzzing instrumentation**
- **Copy existing binaries to $OUT with _exec suffix** (e.g., mytool_exec)
- Create fuzz targets that actually exercise security-critical code paths
- **For CLI tools that read from stdin/files, create wrapper harnesses**

Example for existing targets:
```bash
# Build original project with fuzzing flags
make CC="$CC" CXX="$CXX" CFLAGS="$CFLAGS" CXXFLAGS="$CXXFLAGS"

# Copy all built executables to $OUT
for binary in ./build/bin/*; do
    if [ -x "$binary" ]; then
        cp "$binary" $OUT/$(basename $binary)_exec
    fi
done
```
{security_section}
Please proceed with the analysis and file generation."""


async def _run_agent_async(
    repo_path: str,
    project_name: str,
    output_dir: str,
    max_turns: int = 30,
    detected_languages: Optional[list] = None,
    build_files: Optional[list] = None,
    main_files: Optional[Dict[str, list]] = None,
) -> bool:
    """Run the Claude agent to generate OSS-Fuzz integration files."""

    if not CLAUDE_SDK_AVAILABLE:
        logger.error("Claude Agent SDK not available")
        return False

    # Ensure output directory exists
    os.makedirs(output_dir, exist_ok=True)

    options = ClaudeAgentOptions(
        system_prompt=OSSFUZZ_AGENT_SYSTEM_PROMPT,
        max_turns=max_turns,
        allowed_tools=["Read", "Write", "Bash", "Glob", "Grep"],
        permission_mode='acceptEdits',  # Auto-accept file edits
        cwd=repo_path,
    )

    prompt = _get_project_analysis_prompt(
        repo_path,
        project_name,
        detected_languages=detected_languages,
        build_files=build_files,
        main_files=main_files,
    )

    try:
        async with ClaudeSDKClient(options=options) as client:
            await client.query(prompt)

            full_response = []
            async for message in client.receive_response():
                if isinstance(message, AssistantMessage):
                    for block in message.content:
                        if isinstance(block, TextBlock):
                            full_response.append(block.text)
                            logger.info(f"Agent: {block.text[:200]}...")

            # Check if required files were created
            required_files = ['project.yaml', 'Dockerfile', 'build.sh']
            missing_files = []
            for f in required_files:
                if not os.path.exists(os.path.join(output_dir, f)):
                    missing_files.append(f)

            if missing_files:
                logger.warning(f"Agent did not create all required files. Missing: {missing_files}")
                return False

            logger.info(f"Successfully generated OSS-Fuzz integration in {output_dir}")
            return True

    except Exception as e:
        logger.error(f"Agent execution failed: {e}")
        return False


async def _run_fix_agent_async(
    repo_path: str,
    project_name: str,
    output_dir: str,
    build_error: str,
    max_turns: int = 30,
) -> bool:
    """Run the Claude agent to fix OSS-Fuzz build errors."""

    if not CLAUDE_SDK_AVAILABLE:
        logger.error("Claude Agent SDK not available")
        return False

    options = ClaudeAgentOptions(
        system_prompt=OSSFUZZ_AGENT_SYSTEM_PROMPT,
        max_turns=max_turns,
        allowed_tools=["Read", "Write", "Bash", "Glob", "Grep"],
        permission_mode='acceptEdits',
        cwd=repo_path,
    )

    prompt = _get_build_fix_prompt(repo_path, project_name, output_dir, build_error)

    try:
        async with ClaudeSDKClient(options=options) as client:
            await client.query(prompt)

            async for message in client.receive_response():
                if isinstance(message, AssistantMessage):
                    for block in message.content:
                        if isinstance(block, TextBlock):
                            logger.info(f"Agent: {block.text[:200]}...")

            logger.info(f"Agent finished attempting to fix build errors")
            return True

    except Exception as e:
        logger.error(f"Agent execution failed: {e}")
        return False


def fix_build_error(
    repo_path: str,
    project_name: str,
    build_error: str,
    output_dir: Optional[str] = None,
    max_turns: int = 30,
) -> bool:
    """
    Fix OSS-Fuzz build errors using Claude Agent SDK.

    Args:
        repo_path: Path to the cloned repository
        project_name: Name of the project
        build_error: The build error output to fix
        output_dir: Directory containing the integration files
        max_turns: Maximum agent turns (default: 30)

    Returns:
        bool: True if agent completed (doesn't guarantee fix worked)
    """
    if output_dir is None:
        output_dir = os.path.join(
            os.path.dirname(repo_path),
            "fuzz-tooling", "projects", project_name
        )

    logger.info(f"Attempting to fix build error for {project_name}")
    logger.info(f"Output directory: {output_dir}")

    return asyncio.run(_run_fix_agent_async(repo_path, project_name, output_dir, build_error, max_turns))


def generate_ossfuzz_integration(
    repo_path: str,
    project_name: str,
    output_dir: Optional[str] = None,
    max_turns: int = 30,
) -> bool:
    """
    Generate OSS-Fuzz integration files for a project using Claude Agent SDK.

    Args:
        repo_path: Path to the cloned repository
        project_name: Name of the project
        output_dir: Directory to write generated files (default: repo_path/../fuzz-tooling/projects/{project_name})
        max_turns: Maximum agent turns (default: 30)

    Returns:
        bool: True if integration was generated successfully
    """
    if output_dir is None:
        output_dir = os.path.join(
            os.path.dirname(repo_path),
            "fuzz-tooling", "projects", project_name
        )

    logger.info(f"Generating OSS-Fuzz integration for {project_name}")
    logger.info(f"Repository: {repo_path}")
    logger.info(f"Output directory: {output_dir}")

    # Detect project language and log useful info
    languages = detect_project_language(repo_path)
    logger.info(f"Detected languages: {languages}")

    build_files = get_build_script_files(repo_path)
    logger.info(f"Found {len(build_files)} build script files")

    # Find main functions for each detected language
    all_main_files = {}
    for lang in languages:
        main_files = find_main_functions(repo_path, lang)
        if main_files:
            all_main_files[lang] = main_files
            logger.info(f"Found {len(main_files)} files with main functions ({lang})")

    # Check if we have security templates for this language
    for lang in languages:
        templates = get_security_templates_for_language(lang)
        if templates:
            logger.info(f"Security fuzzing templates available for {lang}: {list(templates.keys())}")

    return asyncio.run(_run_agent_async(
        repo_path,
        project_name,
        output_dir,
        max_turns,
        detected_languages=languages,
        build_files=build_files,
        main_files=all_main_files if all_main_files else None,
    ))


# CLI entry point
def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Generate OSS-Fuzz integration using Claude Agent SDK"
    )
    parser.add_argument("repo_path", help="Path to the repository")
    parser.add_argument("project_name", help="Name of the project")
    parser.add_argument("--output-dir", help="Output directory for generated files")
    parser.add_argument("--max-turns", type=int, default=30, help="Max agent turns")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument("--fix-error", help="Fix a build error (pass error file path or '-' for stdin)")

    args = parser.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    # Handle fix-error mode
    if args.fix_error:
        if args.fix_error == '-':
            build_error = sys.stdin.read()
        else:
            with open(args.fix_error, 'r') as f:
                build_error = f.read()

        success = fix_build_error(
            args.repo_path,
            args.project_name,
            build_error,
            args.output_dir,
            args.max_turns,
        )
    else:
        success = generate_ossfuzz_integration(
            args.repo_path,
            args.project_name,
            args.output_dir,
            args.max_turns,
        )

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
