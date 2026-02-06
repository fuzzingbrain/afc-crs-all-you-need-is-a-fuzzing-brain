#!/usr/bin/env node
/**
 * TaintSan JavaScript Demo
 *
 * Run: node demo.js
 */

'use strict';

const taintsan = require('./taintsan');

// Install monitors
taintsan.install();

console.log('='.repeat(60));
console.log('TaintSan JavaScript Demo - Taint Tracking');
console.log('='.repeat(60));

// ============================================================================
// Demo 1: Basic Taint Tracking
// ============================================================================

console.log('\n--- Demo 1: Basic Taint Tracking ---\n');

const userInput = taintsan.taint("'; DROP TABLE users; --", taintsan.TaintSource.HTTP_REQUEST);

console.log('Original input:', userInput);
console.log('Is tainted:', taintsan.isTainted(userInput));

// Taint propagates through string operations
const upperCase = userInput.toUpperCase();
console.log('After toUpperCase():', upperCase);
console.log('Still tainted:', taintsan.isTainted(upperCase));

const trimmed = userInput.trim();
console.log('After trim():', trimmed);
console.log('Still tainted:', taintsan.isTainted(trimmed));

// ============================================================================
// Demo 2: Taint Propagation through Concatenation
// ============================================================================

console.log('\n--- Demo 2: Taint Propagation ---\n');

const prefix = "SELECT * FROM users WHERE name = '";
const suffix = "'";
const query = prefix + userInput + suffix;

console.log('SQL Query:', query.toString());
console.log('Query is tainted:', taintsan.isTainted(query));

// Using template literals with tagged template
const taggedQuery = taintsan.sql`SELECT * FROM users WHERE id = ${userInput}`;
console.log('Tagged template:', taggedQuery.toString());
console.log('Tagged is tainted:', taintsan.isTainted(taggedQuery));

// ============================================================================
// Demo 3: Detecting Command Injection (Simulated)
// ============================================================================

console.log('\n--- Demo 3: Command Injection Detection ---\n');

function simulateCommandExec(command) {
    console.log(`Simulating exec: ${command}`);

    // Check if tainted
    if (taintsan.isTainted(command)) {
        console.log('\x1b[31m[TAINTSAN] DETECTED: Tainted data in command!\x1b[0m');

        const info = taintsan.getTaintInfo(command);
        if (info) {
            console.log(`  Source: ${info.source}`);
            console.log(`  Origin: ${info.sourceLocation}`);
            console.log(`  Propagation: ${info.propagationChain.join(' -> ')}`);
        }
    }
}

const filename = taintsan.taint('/etc/passwd; rm -rf /', taintsan.TaintSource.FUZZER);
const cmd = 'cat ' + filename;

simulateCommandExec(cmd);

// ============================================================================
// Demo 4: SQL Injection Detection (Simulated)
// ============================================================================

console.log('\n--- Demo 4: SQL Injection Detection ---\n');

function simulateSqlQuery(sql) {
    console.log(`Simulating SQL: ${sql.toString().substring(0, 50)}...`);

    if (taintsan.isTainted(sql)) {
        console.log('\x1b[31m[TAINTSAN] DETECTED: Tainted data in SQL query!\x1b[0m');
        return;
    }

    console.log('\x1b[32m[OK] Query is safe (not tainted)\x1b[0m');
}

// Vulnerable: direct string interpolation
const unsafeQuery = `SELECT * FROM users WHERE name = '${userInput}'`;
simulateSqlQuery(unsafeQuery);

// Safe: using parameterized query (simulated)
const safeQueryTemplate = "SELECT * FROM users WHERE name = ?";
// In a real DB library, params would be escaped, not concatenated
console.log(`Safe query template: ${safeQueryTemplate}`);
console.log('Template is tainted:', taintsan.isTainted(safeQueryTemplate));

// ============================================================================
// Demo 5: Prototype Pollution Detection
// ============================================================================

console.log('\n--- Demo 5: Prototype Pollution Detection ---\n');

const maliciousPayload = taintsan.taint('__proto__', taintsan.TaintSource.FUZZER);

console.log('Malicious key:', maliciousPayload);
console.log('Key is tainted:', taintsan.isTainted(maliciousPayload));

// Simulate checking before property assignment
function safeAssign(obj, key, value) {
    if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
        if (taintsan.isTainted(key)) {
            console.log('\x1b[31m[TAINTSAN] DETECTED: Prototype pollution attempt!\x1b[0m');
            return;
        }
    }
    obj[key] = value;
}

const target = {};
safeAssign(target, maliciousPayload, { polluted: true });

// ============================================================================
// Demo 6: Real Sink Detection (if you want to test)
// ============================================================================

console.log('\n--- Demo 6: Real Sink Detection ---\n');

// Uncomment to test real sink detection (will throw TaintViolationError):

/*
const child_process = require('child_process');
try {
    const taintedCmd = taintsan.taint('echo hello', taintsan.TaintSource.FUZZER);
    child_process.execSync(taintedCmd);  // This will throw!
} catch (e) {
    if (e instanceof taintsan.TaintViolationError) {
        console.log('\x1b[32m[SUCCESS] TaintSan caught the violation!\x1b[0m');
        console.log(e.message);
    } else {
        throw e;
    }
}
*/

// Using eval
try {
    const taintedCode = taintsan.taint('console.log("hello")', taintsan.TaintSource.FUZZER);
    console.log('About to call eval with tainted code...');
    eval(taintedCode.toString());  // Note: need toString() to unwrap
    // If we used the raw TaintedString, it would trigger
} catch (e) {
    if (e instanceof taintsan.TaintViolationError) {
        console.log('\x1b[32m[SUCCESS] TaintSan caught eval violation!\x1b[0m');
    } else {
        console.log('Error:', e.message);
    }
}

// ============================================================================
// Summary
// ============================================================================

console.log('\n' + '='.repeat(60));
console.log('Demo Complete');
console.log('='.repeat(60));

const violations = taintsan.getViolations();
console.log(`\nTotal violations recorded: ${violations.length}`);
violations.forEach((v, i) => {
    console.log(`  ${i + 1}. ${v.sinkType}: ${v.sinkFunction}`);
});

console.log('\nTaintSan successfully demonstrated:');
console.log('  - Taint tracking through string operations');
console.log('  - Propagation through concatenation');
console.log('  - Detection at dangerous sinks');
console.log('  - Tagged template literals for safe queries');
