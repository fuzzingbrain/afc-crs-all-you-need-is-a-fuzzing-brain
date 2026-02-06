/**
 * TaintSan Integration with Jazzer.js
 *
 * This module provides helpers for using TaintSan with Jazzer.js fuzzing.
 *
 * Usage:
 *   const { fuzzWithTaint } = require('./jazzer_integration');
 *
 *   module.exports.fuzz = fuzzWithTaint((data) => {
 *       // data is automatically tainted
 *       myFunction(data.toString());
 *   });
 */

'use strict';

const taintsan = require('./taintsan');

// Install TaintSan monitors at module load time
taintsan.install();

/**
 * Wrapper for Jazzer.js fuzz functions that automatically taints input
 *
 * @param {Function} testFunc - The fuzz test function
 * @returns {Function} - Wrapped function for Jazzer
 */
function fuzzWithTaint(testFunc) {
    return function(data) {
        // Taint the fuzzer input
        const taintedData = taintsan.taintFromFuzzer(data);

        try {
            testFunc(taintedData);
        } catch (e) {
            if (e instanceof taintsan.TaintViolationError) {
                // TaintSan found a vulnerability - this is a "crash"
                console.error('\n[TAINTSAN] Vulnerability detected!');
                console.error(`  Sink: ${e.violation.sinkType} - ${e.violation.sinkFunction}`);
                console.error(`  Source: ${e.violation.taintInfo.source}`);
                console.error(`  Value: ${e.violation.taintedValuePreview}`);
                throw e;  // Re-throw for Jazzer to catch
            }
            // Other exceptions - let Jazzer handle them
            throw e;
        }
    };
}

/**
 * Wrapper that converts Buffer to tainted string
 */
function fuzzStringWithTaint(testFunc) {
    return fuzzWithTaint((data) => {
        // Convert Buffer to tainted string
        const str = data.toString('utf-8');
        const taintedStr = taintsan.taint(str, taintsan.TaintSource.FUZZER);
        testFunc(taintedStr);
    });
}

/**
 * Wrapper for testing JSON input
 */
function fuzzJSONWithTaint(testFunc) {
    return fuzzWithTaint((data) => {
        try {
            const jsonStr = data.toString('utf-8');
            const parsed = JSON.parse(jsonStr);

            // Deep taint all string values in the parsed object
            const taintedObj = deepTaintObject(parsed);
            testFunc(taintedObj);
        } catch (e) {
            if (e instanceof SyntaxError) {
                // Invalid JSON - expected during fuzzing
                return;
            }
            throw e;
        }
    });
}

/**
 * Deep taint all string values in an object
 */
function deepTaintObject(obj, visited = new WeakSet()) {
    if (obj === null || obj === undefined) {
        return obj;
    }

    if (typeof obj === 'string') {
        return taintsan.taint(obj, taintsan.TaintSource.FUZZER);
    }

    if (typeof obj !== 'object') {
        return obj;
    }

    // Prevent infinite loops with circular references
    if (visited.has(obj)) {
        return obj;
    }
    visited.add(obj);

    if (Array.isArray(obj)) {
        return obj.map(item => deepTaintObject(item, visited));
    }

    const result = {};
    for (const [key, value] of Object.entries(obj)) {
        // Taint the key if it's a string
        const taintedKey = typeof key === 'string'
            ? taintsan.taint(key, taintsan.TaintSource.FUZZER)
            : key;

        result[taintedKey] = deepTaintObject(value, visited);
    }

    return result;
}

// ============================================================================
// Example Fuzz Targets
// ============================================================================

/**
 * Example: SQL Injection Detection
 */
const fuzzSQLInjection = fuzzStringWithTaint((userInput) => {
    // Simulated SQL query construction (vulnerable)
    const query = `SELECT * FROM users WHERE name = '${userInput}'`;

    // In a real scenario, this would execute the query
    // For demo, we check manually:
    if (userInput.includes("'") || userInput.toLowerCase().includes('union')) {
        // Simulate what would happen if this reached a DB
        const mockDb = {
            execute: (sql) => {
                taintsan.checkSink?.(taintsan.SinkType.SQL_QUERY, 'db.execute', sql);
            }
        };
        // This would trigger TaintSan if execute() is properly hooked
    }
});

/**
 * Example: Command Injection Detection
 */
const fuzzCommandInjection = fuzzStringWithTaint((userInput) => {
    const child_process = require('child_process');

    // Vulnerable: user input directly in command
    // TaintSan will catch this!
    try {
        child_process.execSync(`echo ${userInput}`, { encoding: 'utf-8' });
    } catch (e) {
        if (e instanceof taintsan.TaintViolationError) {
            throw e;  // This is what we want to detect!
        }
        // Other errors (command failed) are expected
    }
});

/**
 * Example: Prototype Pollution Detection
 */
const fuzzPrototypePollution = fuzzJSONWithTaint((obj) => {
    // Vulnerable merge function
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

    // Check for prototype pollution attempt
    if (obj && (obj.__proto__ || obj.constructor || obj.prototype)) {
        // This is a potential pollution attempt
        // In real code, the merge would pollute Object.prototype
    }

    const config = {};
    vulnerableMerge(config, obj);
});

/**
 * Example: Path Traversal Detection
 */
const fuzzPathTraversal = fuzzStringWithTaint((userPath) => {
    const fs = require('fs');
    const path = require('path');

    // Attempt to read file with user-controlled path
    // TaintSan will catch this!
    const fullPath = path.join('/var/www/files', userPath);

    try {
        // This will trigger TaintSan if userPath contains traversal
        fs.readFileSync(fullPath);
    } catch (e) {
        if (e instanceof taintsan.TaintViolationError) {
            throw e;
        }
        // File not found, etc. - expected
    }
});

// ============================================================================
// Exports
// ============================================================================

module.exports = {
    // Core wrappers
    fuzzWithTaint,
    fuzzStringWithTaint,
    fuzzJSONWithTaint,
    deepTaintObject,

    // Example fuzz targets
    examples: {
        fuzzSQLInjection,
        fuzzCommandInjection,
        fuzzPrototypePollution,
        fuzzPathTraversal,
    },

    // Re-export taintsan for convenience
    taintsan,
};
