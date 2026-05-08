// SPDX-License-Identifier: Apache-2.0
/**
 * TaintSan - Taint Tracking Sanitizer for JavaScript/Node.js
 *
 * Tracks "tainted" data from untrusted sources and detects when it reaches
 * dangerous sinks without proper sanitization.
 *
 * Usage:
 *   const taintsan = require('./taintsan');
 *   taintsan.install();
 *
 *   const userInput = taintsan.taint(req.body.name, 'HTTP_REQUEST');
 *   // ... use userInput, taint propagates automatically ...
 *
 * @author AFC-CRS Security Research
 */

'use strict';

// ============================================================================
// Configuration
// ============================================================================

const config = {
    // Behavior on taint violation
    throwOnSink: true,          // Throw error when tainted data hits sink
    logViolations: true,        // Log violations to console/file
    logFile: '/tmp/taintsan_js_violations.log',

    // What to monitor
    monitorEval: true,
    monitorChildProcess: true,
    monitorFileSystem: true,
    monitorNetwork: true,
    monitorSQL: true,
    monitorPrototypePollution: true,

    // Taint propagation
    propagateThroughJSON: true,
    maxPropagationChainLength: 100,
};

// ============================================================================
// Taint Source Types
// ============================================================================

const TaintSource = {
    FUZZER: 'FUZZER',
    HTTP_REQUEST: 'HTTP_REQUEST',
    FILE_INPUT: 'FILE_INPUT',
    STDIN: 'STDIN',
    ENV_VAR: 'ENV_VAR',
    DATABASE: 'DATABASE',
    NETWORK: 'NETWORK',
    USER_MARKED: 'USER_MARKED',
};

// ============================================================================
// Sink Types
// ============================================================================

const SinkType = {
    EVAL: 'EVAL',
    FUNCTION_CONSTRUCTOR: 'FUNCTION_CONSTRUCTOR',
    CHILD_PROCESS: 'CHILD_PROCESS',
    FILE_PATH: 'FILE_PATH',
    FILE_WRITE: 'FILE_WRITE',
    NETWORK_REQUEST: 'NETWORK_REQUEST',
    SQL_QUERY: 'SQL_QUERY',
    PROTOTYPE_POLLUTION: 'PROTOTYPE_POLLUTION',
    INNER_HTML: 'INNER_HTML',
    DOCUMENT_WRITE: 'DOCUMENT_WRITE',
};

// ============================================================================
// Taint Metadata Storage
// ============================================================================

// WeakMap to store taint info for objects (won't prevent GC)
const taintMap = new WeakMap();

// Map for primitives (strings) - uses string value as key
// Note: This can grow, so we limit it
const stringTaintMap = new Map();
const MAX_STRING_TAINT_ENTRIES = 10000;

// Taint ID counter
let taintIdCounter = 0;

/**
 * Taint metadata structure
 */
class TaintInfo {
    constructor(source, sourceLocation, originalValue) {
        this.taintId = ++taintIdCounter;
        this.source = source;
        this.sourceLocation = sourceLocation;
        this.timestamp = Date.now();
        this.originalValueHash = this._hashValue(originalValue);
        this.propagationChain = [];
    }

    _hashValue(value) {
        // Simple hash for tracking
        const str = String(value).substring(0, 1000);
        let hash = 0;
        for (let i = 0; i < str.length; i++) {
            const char = str.charCodeAt(i);
            hash = ((hash << 5) - hash) + char;
            hash = hash & hash;
        }
        return hash;
    }

    addPropagation(operation, location) {
        if (this.propagationChain.length < config.maxPropagationChainLength) {
            this.propagationChain.push(`${operation}@${location}`);
        }
    }

    clone() {
        const cloned = new TaintInfo(this.source, this.sourceLocation, null);
        cloned.taintId = this.taintId;
        cloned.timestamp = this.timestamp;
        cloned.originalValueHash = this.originalValueHash;
        cloned.propagationChain = [...this.propagationChain];
        return cloned;
    }
}

// ============================================================================
// Violation Tracking
// ============================================================================

const violations = [];

class TaintViolation {
    constructor(sinkType, sinkFunction, sinkLocation, taintInfo, taintedValue) {
        this.sinkType = sinkType;
        this.sinkFunction = sinkFunction;
        this.sinkLocation = sinkLocation;
        this.taintInfo = taintInfo;
        this.taintedValuePreview = String(taintedValue).substring(0, 200);
        this.timestamp = Date.now();
        this.stackTrace = new Error().stack;
    }
}

class TaintViolationError extends Error {
    constructor(violation) {
        super(
            `TAINT VIOLATION: ${violation.sinkType} sink '${violation.sinkFunction}' ` +
            `received tainted data from ${violation.taintInfo.source} ` +
            `(origin: ${violation.taintInfo.sourceLocation})`
        );
        this.name = 'TaintViolationError';
        this.violation = violation;
    }
}

function reportViolation(sinkType, sinkFunction, taintInfo, taintedValue) {
    const location = getCallerLocation(3);
    const violation = new TaintViolation(
        sinkType, sinkFunction, location, taintInfo, taintedValue
    );

    violations.push(violation);

    if (config.logViolations) {
        logViolation(violation);
    }

    if (config.throwOnSink) {
        throw new TaintViolationError(violation);
    }
}

function logViolation(violation) {
    const fs = require('fs');
    const message = `
================================================================================
TAINT VIOLATION DETECTED
Time: ${new Date(violation.timestamp).toISOString()}
Sink Type: ${violation.sinkType}
Sink Function: ${violation.sinkFunction}
Sink Location: ${violation.sinkLocation}
Taint Source: ${violation.taintInfo.source}
Taint Origin: ${violation.taintInfo.sourceLocation}
Tainted Value: ${violation.taintedValuePreview}
Propagation Chain:
${violation.taintInfo.propagationChain.map(s => '  -> ' + s).join('\n')}
Stack Trace:
${violation.stackTrace}
================================================================================
`;

    console.error('\x1b[31m[TAINTSAN]\x1b[0m', message);

    try {
        fs.appendFileSync(config.logFile, message);
    } catch (e) {
        // Ignore file write errors
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

function getCallerLocation(depth = 2) {
    const stack = new Error().stack.split('\n');
    if (stack.length > depth + 1) {
        const line = stack[depth + 1];
        const match = line.match(/at\s+(.+)\s+\((.+):(\d+):(\d+)\)/) ||
                      line.match(/at\s+(.+):(\d+):(\d+)/);
        if (match) {
            return match[0];
        }
    }
    return 'unknown';
}

function isTainted(value) {
    if (value === null || value === undefined) {
        return false;
    }

    // Check objects in WeakMap
    if (typeof value === 'object') {
        return taintMap.has(value);
    }

    // Check strings in string map
    if (typeof value === 'string') {
        return stringTaintMap.has(value);
    }

    return false;
}

function getTaintInfo(value) {
    if (value === null || value === undefined) {
        return null;
    }

    if (typeof value === 'object') {
        return taintMap.get(value);
    }

    if (typeof value === 'string') {
        return stringTaintMap.get(value);
    }

    return null;
}

function setTaintInfo(value, taintInfo) {
    if (value === null || value === undefined) {
        return;
    }

    if (typeof value === 'object') {
        taintMap.set(value, taintInfo);
    } else if (typeof value === 'string') {
        // Limit string taint map size
        if (stringTaintMap.size >= MAX_STRING_TAINT_ENTRIES) {
            // Remove oldest entries
            const keys = Array.from(stringTaintMap.keys()).slice(0, 1000);
            keys.forEach(k => stringTaintMap.delete(k));
        }
        stringTaintMap.set(value, taintInfo);
    }
}

function anyTainted(values) {
    if (!values) return false;

    if (Array.isArray(values)) {
        return values.some(v => isTainted(v) || anyTainted(v));
    }

    if (typeof values === 'object') {
        return Object.values(values).some(v => isTainted(v) || anyTainted(v));
    }

    return isTainted(values);
}

function getAnyTaintInfo(values) {
    if (!values) return null;

    if (isTainted(values)) {
        return getTaintInfo(values);
    }

    if (Array.isArray(values)) {
        for (const v of values) {
            const info = getAnyTaintInfo(v);
            if (info) return info;
        }
    }

    if (typeof values === 'object') {
        for (const v of Object.values(values)) {
            const info = getAnyTaintInfo(v);
            if (info) return info;
        }
    }

    return null;
}

// ============================================================================
// Tainted String Class
// ============================================================================

/**
 * TaintedString - A string wrapper that tracks taint
 *
 * Note: JavaScript strings are immutable primitives, so we create a
 * String object wrapper that behaves like a string but carries taint info.
 */
class TaintedString extends String {
    constructor(value, taintInfo) {
        super(value);
        this._taintInfo = taintInfo;
        this._value = String(value);
    }

    get taintInfo() {
        return this._taintInfo;
    }

    isTainted() {
        return this._taintInfo !== null;
    }

    _propagateTaint(result, operation) {
        if (!this._taintInfo) {
            return result;
        }

        const newInfo = this._taintInfo.clone();
        newInfo.addPropagation(operation, getCallerLocation());

        return new TaintedString(result, newInfo);
    }

    // Override string methods to propagate taint
    concat(...strings) {
        const result = this._value.concat(...strings.map(s => String(s)));

        // Check if any input is tainted
        const taintedInput = [this, ...strings].find(s =>
            s instanceof TaintedString || isTainted(s)
        );

        if (taintedInput) {
            const info = taintedInput instanceof TaintedString
                ? taintedInput._taintInfo
                : getTaintInfo(taintedInput);
            if (info) {
                const newInfo = info.clone();
                newInfo.addPropagation('concat', getCallerLocation());
                return new TaintedString(result, newInfo);
            }
        }

        return result;
    }

    slice(start, end) {
        return this._propagateTaint(this._value.slice(start, end), 'slice');
    }

    substring(start, end) {
        return this._propagateTaint(this._value.substring(start, end), 'substring');
    }

    substr(start, length) {
        return this._propagateTaint(this._value.substr(start, length), 'substr');
    }

    toLowerCase() {
        return this._propagateTaint(this._value.toLowerCase(), 'toLowerCase');
    }

    toUpperCase() {
        return this._propagateTaint(this._value.toUpperCase(), 'toUpperCase');
    }

    trim() {
        return this._propagateTaint(this._value.trim(), 'trim');
    }

    trimStart() {
        return this._propagateTaint(this._value.trimStart(), 'trimStart');
    }

    trimEnd() {
        return this._propagateTaint(this._value.trimEnd(), 'trimEnd');
    }

    replace(searchValue, replaceValue) {
        const result = this._value.replace(searchValue, replaceValue);

        // Propagate taint if either this string or replacement is tainted
        if (this._taintInfo) {
            return this._propagateTaint(result, 'replace');
        }
        if (isTainted(replaceValue)) {
            const info = getTaintInfo(replaceValue);
            return new TaintedString(result, info);
        }
        return result;
    }

    replaceAll(searchValue, replaceValue) {
        const result = this._value.replaceAll(searchValue, replaceValue);

        if (this._taintInfo) {
            return this._propagateTaint(result, 'replaceAll');
        }
        if (isTainted(replaceValue)) {
            const info = getTaintInfo(replaceValue);
            return new TaintedString(result, info);
        }
        return result;
    }

    split(separator, limit) {
        const parts = this._value.split(separator, limit);

        if (this._taintInfo) {
            return parts.map(part => this._propagateTaint(part, 'split'));
        }
        return parts;
    }

    padStart(targetLength, padString) {
        return this._propagateTaint(
            this._value.padStart(targetLength, padString), 'padStart'
        );
    }

    padEnd(targetLength, padString) {
        return this._propagateTaint(
            this._value.padEnd(targetLength, padString), 'padEnd'
        );
    }

    repeat(count) {
        return this._propagateTaint(this._value.repeat(count), 'repeat');
    }

    // Conversion methods
    toString() {
        return this._value;
    }

    valueOf() {
        return this._value;
    }

    // JSON serialization
    toJSON() {
        return this._value;
    }

    // Allow primitive coercion
    [Symbol.toPrimitive](hint) {
        if (hint === 'number') {
            return Number(this._value);
        }
        return this._value;
    }
}

// ============================================================================
// Public API: Taint Functions
// ============================================================================

/**
 * Mark a value as tainted
 * @param {*} value - The value to taint
 * @param {string} source - The taint source (from TaintSource)
 * @returns {*} - The tainted value
 */
function taint(value, source = TaintSource.USER_MARKED) {
    const taintInfo = new TaintInfo(source, getCallerLocation(), value);

    if (typeof value === 'string') {
        return new TaintedString(value, taintInfo);
    }

    if (Buffer.isBuffer(value)) {
        // For buffers, store taint info in the map
        setTaintInfo(value, taintInfo);
        return value;
    }

    if (typeof value === 'object' && value !== null) {
        setTaintInfo(value, taintInfo);
        return value;
    }

    // For other primitives, we can't easily taint them
    // Return as-is but log warning
    console.warn('[TaintSan] Cannot taint primitive:', typeof value);
    return value;
}

/**
 * Convenience function for tainting fuzzer input
 */
function taintFromFuzzer(data) {
    return taint(data, TaintSource.FUZZER);
}

/**
 * Check if a value is tainted
 */
function checkTainted(value) {
    if (value instanceof TaintedString) {
        return value.isTainted();
    }
    return isTainted(value);
}

/**
 * Get all recorded violations
 */
function getViolations() {
    return [...violations];
}

/**
 * Clear all recorded violations
 */
function clearViolations() {
    violations.length = 0;
}

// ============================================================================
// Sink Monitors
// ============================================================================

const originalFunctions = {};

function checkSink(sinkType, sinkName, ...args) {
    for (const arg of args) {
        if (arg instanceof TaintedString && arg.isTainted()) {
            reportViolation(sinkType, sinkName, arg._taintInfo, arg);
        } else if (isTainted(arg)) {
            const info = getTaintInfo(arg);
            if (info) {
                reportViolation(sinkType, sinkName, info, arg);
            }
        } else if (anyTainted(arg)) {
            const info = getAnyTaintInfo(arg);
            if (info) {
                reportViolation(sinkType, sinkName, info, arg);
            }
        }
    }
}

function wrapSink(originalFunc, sinkType, sinkName) {
    return function(...args) {
        checkSink(sinkType, sinkName, ...args);
        return originalFunc.apply(this, args);
    };
}

// ============================================================================
// Install Monitors
// ============================================================================

function installEvalMonitor() {
    if (!config.monitorEval) return;

    // eval
    originalFunctions['eval'] = global.eval;
    global.eval = wrapSink(global.eval, SinkType.EVAL, 'eval');

    // Function constructor
    originalFunctions['Function'] = global.Function;
    global.Function = new Proxy(Function, {
        construct(target, args) {
            checkSink(SinkType.FUNCTION_CONSTRUCTOR, 'new Function()', ...args);
            return new target(...args);
        },
        apply(target, thisArg, args) {
            checkSink(SinkType.FUNCTION_CONSTRUCTOR, 'Function()', ...args);
            return target.apply(thisArg, args);
        }
    });
}

function installChildProcessMonitor() {
    if (!config.monitorChildProcess) return;

    try {
        const childProcess = require('child_process');

        // exec
        originalFunctions['child_process.exec'] = childProcess.exec;
        childProcess.exec = function(command, options, callback) {
            checkSink(SinkType.CHILD_PROCESS, 'child_process.exec', command);
            return originalFunctions['child_process.exec'].call(this, command, options, callback);
        };

        // execSync
        originalFunctions['child_process.execSync'] = childProcess.execSync;
        childProcess.execSync = function(command, options) {
            checkSink(SinkType.CHILD_PROCESS, 'child_process.execSync', command);
            return originalFunctions['child_process.execSync'].call(this, command, options);
        };

        // spawn
        originalFunctions['child_process.spawn'] = childProcess.spawn;
        childProcess.spawn = function(command, args, options) {
            checkSink(SinkType.CHILD_PROCESS, 'child_process.spawn', command, args);
            return originalFunctions['child_process.spawn'].call(this, command, args, options);
        };

        // spawnSync
        originalFunctions['child_process.spawnSync'] = childProcess.spawnSync;
        childProcess.spawnSync = function(command, args, options) {
            checkSink(SinkType.CHILD_PROCESS, 'child_process.spawnSync', command, args);
            return originalFunctions['child_process.spawnSync'].call(this, command, args, options);
        };

        // execFile
        originalFunctions['child_process.execFile'] = childProcess.execFile;
        childProcess.execFile = function(file, args, options, callback) {
            checkSink(SinkType.CHILD_PROCESS, 'child_process.execFile', file, args);
            return originalFunctions['child_process.execFile'].call(this, file, args, options, callback);
        };

        // fork
        originalFunctions['child_process.fork'] = childProcess.fork;
        childProcess.fork = function(modulePath, args, options) {
            checkSink(SinkType.CHILD_PROCESS, 'child_process.fork', modulePath, args);
            return originalFunctions['child_process.fork'].call(this, modulePath, args, options);
        };

    } catch (e) {
        // child_process not available (browser environment)
    }
}

function installFileSystemMonitor() {
    if (!config.monitorFileSystem) return;

    try {
        const fs = require('fs');

        const fsMethodsToWrap = [
            'readFile', 'readFileSync',
            'writeFile', 'writeFileSync',
            'appendFile', 'appendFileSync',
            'unlink', 'unlinkSync',
            'rmdir', 'rmdirSync',
            'rm', 'rmSync',
            'rename', 'renameSync',
            'mkdir', 'mkdirSync',
            'open', 'openSync',
            'readdir', 'readdirSync',
        ];

        fsMethodsToWrap.forEach(method => {
            if (fs[method]) {
                originalFunctions[`fs.${method}`] = fs[method];
                fs[method] = function(path, ...args) {
                    checkSink(SinkType.FILE_PATH, `fs.${method}`, path);
                    return originalFunctions[`fs.${method}`].call(this, path, ...args);
                };
            }
        });

    } catch (e) {
        // fs not available
    }
}

function installNetworkMonitor() {
    if (!config.monitorNetwork) return;

    // http/https
    try {
        ['http', 'https'].forEach(protocol => {
            const module = require(protocol);

            originalFunctions[`${protocol}.request`] = module.request;
            module.request = function(url, options, callback) {
                checkSink(SinkType.NETWORK_REQUEST, `${protocol}.request`, url, options);
                return originalFunctions[`${protocol}.request`].call(this, url, options, callback);
            };

            originalFunctions[`${protocol}.get`] = module.get;
            module.get = function(url, options, callback) {
                checkSink(SinkType.NETWORK_REQUEST, `${protocol}.get`, url, options);
                return originalFunctions[`${protocol}.get`].call(this, url, options, callback);
            };
        });
    } catch (e) {
        // http/https not available
    }

    // fetch (if available)
    if (typeof global.fetch === 'function') {
        originalFunctions['fetch'] = global.fetch;
        global.fetch = function(url, options) {
            checkSink(SinkType.NETWORK_REQUEST, 'fetch', url, options);
            return originalFunctions['fetch'].call(this, url, options);
        };
    }
}

function installPrototypePollutionMonitor() {
    if (!config.monitorPrototypePollution) return;

    // Monitor Object.defineProperty
    originalFunctions['Object.defineProperty'] = Object.defineProperty;
    Object.defineProperty = function(obj, prop, descriptor) {
        if (prop === '__proto__' || prop === 'constructor' || prop === 'prototype') {
            if (isTainted(prop) || anyTainted(descriptor)) {
                const info = getTaintInfo(prop) || getAnyTaintInfo(descriptor);
                if (info) {
                    reportViolation(
                        SinkType.PROTOTYPE_POLLUTION,
                        'Object.defineProperty',
                        info,
                        { obj, prop, descriptor }
                    );
                }
            }
        }
        return originalFunctions['Object.defineProperty'].call(this, obj, prop, descriptor);
    };

    // Monitor object assignment to dangerous properties
    // This requires Proxy wrapping of objects
}

function installSQLMonitor() {
    if (!config.monitorSQL) return;

    // Common SQL libraries

    // mysql / mysql2
    try {
        const mysql = require('mysql2') || require('mysql');
        if (mysql.createConnection) {
            const origCreateConnection = mysql.createConnection;
            mysql.createConnection = function(config) {
                const conn = origCreateConnection(config);

                const origQuery = conn.query;
                conn.query = function(sql, values, callback) {
                    checkSink(SinkType.SQL_QUERY, 'mysql.query', sql, values);
                    return origQuery.call(this, sql, values, callback);
                };

                return conn;
            };
        }
    } catch (e) {
        // mysql not available
    }

    // pg (PostgreSQL)
    try {
        const { Client, Pool } = require('pg');

        const wrapPgClient = (ClientClass) => {
            const origQuery = ClientClass.prototype.query;
            ClientClass.prototype.query = function(sql, values, callback) {
                checkSink(SinkType.SQL_QUERY, 'pg.query', sql, values);
                return origQuery.call(this, sql, values, callback);
            };
        };

        if (Client) wrapPgClient(Client);
        if (Pool) wrapPgClient(Pool);
    } catch (e) {
        // pg not available
    }

    // better-sqlite3
    try {
        const Database = require('better-sqlite3');
        const origPrepare = Database.prototype.prepare;
        Database.prototype.prepare = function(sql) {
            checkSink(SinkType.SQL_QUERY, 'sqlite.prepare', sql);
            return origPrepare.call(this, sql);
        };
    } catch (e) {
        // better-sqlite3 not available
    }
}

// ============================================================================
// String Template Literal Tagging
// ============================================================================

/**
 * Tagged template literal that propagates taint
 *
 * Usage:
 *   const query = taintsan.sql`SELECT * FROM users WHERE name = ${userInput}`;
 */
function taggedTaint(strings, ...values) {
    let result = strings[0];
    let hasTaint = false;
    let taintInfo = null;

    for (let i = 0; i < values.length; i++) {
        const value = values[i];

        if (value instanceof TaintedString && value.isTainted()) {
            hasTaint = true;
            taintInfo = taintInfo || value._taintInfo;
        } else if (isTainted(value)) {
            hasTaint = true;
            taintInfo = taintInfo || getTaintInfo(value);
        }

        result += String(value) + strings[i + 1];
    }

    if (hasTaint && taintInfo) {
        const newInfo = taintInfo.clone();
        newInfo.addPropagation('template_literal', getCallerLocation());
        return new TaintedString(result, newInfo);
    }

    return result;
}

// ============================================================================
// Main Install/Uninstall
// ============================================================================

let installed = false;

function install() {
    if (installed) {
        console.warn('[TaintSan] Already installed');
        return;
    }

    console.error('[TaintSan] Installing taint tracking monitors...');

    installEvalMonitor();
    installChildProcessMonitor();
    installFileSystemMonitor();
    installNetworkMonitor();
    installPrototypePollutionMonitor();
    installSQLMonitor();

    installed = true;
    console.error('[TaintSan] Monitors installed successfully');
}

function uninstall() {
    if (!installed) {
        return;
    }

    console.error('[TaintSan] Uninstalling monitors...');

    // Restore original functions
    if (originalFunctions['eval']) {
        global.eval = originalFunctions['eval'];
    }

    if (originalFunctions['Function']) {
        global.Function = originalFunctions['Function'];
    }

    // Restore other functions...
    // (In a full implementation, we'd restore all wrapped functions)

    installed = false;
    console.error('[TaintSan] Monitors uninstalled');
}

// ============================================================================
// Exports
// ============================================================================

module.exports = {
    // Configuration
    config,

    // Constants
    TaintSource,
    SinkType,

    // Classes
    TaintedString,
    TaintInfo,
    TaintViolation,
    TaintViolationError,

    // Core functions
    taint,
    taintFromFuzzer,
    isTainted: checkTainted,
    getTaintInfo,

    // Violation tracking
    getViolations,
    clearViolations,

    // Installation
    install,
    uninstall,

    // Template literal
    t: taggedTaint,
    sql: taggedTaint,  // Alias for SQL queries
};
