import * as jsSrpClient from '@ruc-cheese/secure-remote-password/client.js';
import * as jsSrpServer from '@ruc-cheese/secure-remote-password/server.js';
import * as origSrpClient from 'secure-remote-password/client.js';
import * as origSrpServer from 'secure-remote-password/server.js';

import { Client as RustSrpClient, Server as RustSrpServer } from './index.js';

import Table from 'cli-table3';
import colors from 'colors';

// Initialize clients
const rustClient = new RustSrpClient();
const rustServer = new RustSrpServer();

// Test data
const TEST_USERNAME = 'test_user@example.com';
const TEST_PASSWORD = 'secure_password123!';

// Main benchmark function
function runBenchmark(iterations = 100) {
    console.log(`\n${colors.cyan('SRP Performance Benchmark')}`);
    console.log(`Running ${iterations} iterations for each operation...\n`);
    
    const results = {};
    
    // Test salt generation
    results.saltGeneration = measureOperation(
        'Salt Generation', 
        iterations,
        () => origSrpClient.generateSalt(),
        () => jsSrpClient.generateSalt(),
        () => rustClient.generateSalt()
    );
    
    // Get a salt for subsequent tests
    const salt = jsSrpClient.generateSalt();
    
    // Test private key derivation
    results.privateKeyDerivation = measureOperation(
        'Private Key Derivation',
        iterations,
        () => origSrpClient.derivePrivateKey(salt, TEST_USERNAME, TEST_PASSWORD),
        () => jsSrpClient.derivePrivateKey(salt, TEST_USERNAME, TEST_PASSWORD),
        () => rustClient.derivePrivateKey(salt, TEST_USERNAME, TEST_PASSWORD)
    );
    
    // Get private key for subsequent tests
    const privateKey = jsSrpClient.derivePrivateKey(salt, TEST_USERNAME, TEST_PASSWORD);
    
    // Test verifier generation
    results.verifierGeneration = measureOperation(
        'Verifier Generation',
        iterations,
        () => origSrpClient.deriveVerifier(privateKey),
        () => jsSrpClient.deriveVerifier(privateKey),
        () => rustClient.deriveVerifier(privateKey)
    );
    
    // Get verifier for subsequent tests
    const verifier = jsSrpClient.deriveVerifier(privateKey);
    
    // Test client ephemeral key generation
    results.clientEphemeralGeneration = measureOperation(
        'Client Ephemeral Generation',
        iterations,
        () => origSrpClient.generateEphemeral(),
        () => jsSrpClient.generateEphemeral(),
        () => rustClient.generateEphemeral()
    );
    
    // Test server ephemeral key generation
    results.serverEphemeralGeneration = measureOperation(
        'Server Ephemeral Generation',
        iterations,
        () => origSrpServer.generateEphemeral(verifier),
        () => jsSrpServer.generateEphemeral(verifier),
        () => rustServer.generateEphemeral(verifier)
    );
    
    // Get client and server ephemeral keys for session tests
    const clientEphemeral = jsSrpClient.generateEphemeral();
    const serverEphemeral = jsSrpServer.generateEphemeral(verifier);
    
    // Test client session derivation
    results.clientSessionDerivation = measureOperation(
        'Client Session Derivation',
        iterations,
        () => origSrpClient.deriveSession(
            clientEphemeral.secret,
            serverEphemeral.public,
            salt,
            TEST_USERNAME,
            privateKey
        ),
        () => jsSrpClient.deriveSession(
            clientEphemeral.secret,
            serverEphemeral.public,
            salt,
            TEST_USERNAME,
            privateKey
        ),
        () => rustClient.deriveSession(
            clientEphemeral.secret,
            serverEphemeral.public,
            salt,
            TEST_USERNAME,
            privateKey
        )
    );
    
    // Get client session for server verification
    const clientSession = jsSrpClient.deriveSession(
        clientEphemeral.secret,
        serverEphemeral.public,
        salt,
        TEST_USERNAME,
        privateKey
    );
    
    // Test server session derivation (including client verification)
    results.serverSessionDerivation = measureOperation(
        'Server Session Derivation',
        iterations,
        () => origSrpServer.deriveSession(
            serverEphemeral.secret,
            clientEphemeral.public,
            salt,
            TEST_USERNAME,
            verifier,
            clientSession.proof
        ),
        () => jsSrpServer.deriveSession(
            serverEphemeral.secret,
            clientEphemeral.public,
            salt,
            TEST_USERNAME,
            verifier,
            clientSession.proof
        ),
        () => rustServer.deriveSession(
            serverEphemeral.secret,
            clientEphemeral.public,
            salt,
            TEST_USERNAME,
            verifier,
            clientSession.proof
        )
    );
    
    // Test complete authentication flow
    results.completeAuthFlow = measureOperation(
        'Complete Authentication Flow',
        iterations / 10, // Reduce iterations as this is a complete flow
        () => {
            // Original JavaScript (jsbn) complete flow
            const origClientEphemeral = origSrpClient.generateEphemeral();
            const origServerEphemeral = origSrpServer.generateEphemeral(verifier);
            const origClientSession = origSrpClient.deriveSession(
                origClientEphemeral.secret,
                origServerEphemeral.public,
                salt,
                TEST_USERNAME,
                privateKey
            );
            const origServerSession = origSrpServer.deriveSession(
                origServerEphemeral.secret,
                origClientEphemeral.public,
                salt,
                TEST_USERNAME,
                verifier,
                origClientSession.proof
            );
            return origServerSession;
        },
        () => {
            // JavaScript (using native BigInt) complete flow
            const jsClientEphemeral = jsSrpClient.generateEphemeral();
            const jsServerEphemeral = jsSrpServer.generateEphemeral(verifier);
            const jsClientSession = jsSrpClient.deriveSession(
                jsClientEphemeral.secret,
                jsServerEphemeral.public,
                salt,
                TEST_USERNAME,
                privateKey
            );
            const jsServerSession = jsSrpServer.deriveSession(
                jsServerEphemeral.secret,
                jsClientEphemeral.public,
                salt,
                TEST_USERNAME,
                verifier,
                jsClientSession.proof
            );
            return jsServerSession;
        },
        () => {
            // Rust complete flow
            const rustClientEphemeral = rustClient.generateEphemeral();
            const rustServerEphemeral = rustServer.generateEphemeral(verifier);
            const rustClientSession = rustClient.deriveSession(
                rustClientEphemeral.secret,
                rustServerEphemeral.public,
                salt,
                TEST_USERNAME,
                privateKey
            );
            const rustServerSession = rustServer.deriveSession(
                rustServerEphemeral.secret,
                rustClientEphemeral.public,
                salt,
                TEST_USERNAME,
                verifier,
                rustClientSession.proof
            );
            return rustServerSession;
        }
    );
    
    // Display benchmark summary
    displaySummary(results);
}

// Measure operation performance
function measureOperation(name, iterations, origFunc, jsFunc, rustFunc) {
    console.log(`Testing ${colors.yellow(name)}...`);
    
    // Original JavaScript (jsbn) performance test
    const origStart = process.hrtime.bigint();
    for (let i = 0; i < iterations; i++) {
        origFunc();
    }
    const origEnd = process.hrtime.bigint();
    const origTime = Number(origEnd - origStart) / 1_000_000;
    
    // JavaScript (using native BigInt) performance test
    const jsStart = process.hrtime.bigint();
    for (let i = 0; i < iterations; i++) {
        jsFunc();
    }
    const jsEnd = process.hrtime.bigint();
    const jsTime = Number(jsEnd - jsStart) / 1_000_000;
    
    // Rust performance test
    const rustStart = process.hrtime.bigint();
    for (let i = 0; i < iterations; i++) {
        rustFunc();
    }
    const rustEnd = process.hrtime.bigint();
    const rustTime = Number(rustEnd - rustStart) / 1_000_000;
    
    // Calculate time per operation
    const origTimePerOp = origTime / iterations;
    const jsTimePerOp = jsTime / iterations;
    const rustTimePerOp = rustTime / iterations;
    
    // Calculate speedup ratio (relative to original jsbn implementation)
    const jsSpeedup = origTimePerOp / jsTimePerOp;
    const rustSpeedup = origTimePerOp / rustTimePerOp;
    
    console.log(`  Original JS (jsbn):   ${origTime.toFixed(2)}ms total, ${origTimePerOp.toFixed(2)}ms per operation`);
    console.log(`  JS (native BigInt):   ${jsTime.toFixed(2)}ms total, ${jsTimePerOp.toFixed(2)}ms per operation`);
    console.log(`  Rust:                 ${rustTime.toFixed(2)}ms total, ${rustTimePerOp.toFixed(2)}ms per operation`);
    console.log(`  BigInt vs jsbn:       ${colors.green(jsSpeedup.toFixed(2) + 'x')}`);
    console.log(`  Rust vs jsbn:         ${colors.green(rustSpeedup.toFixed(2) + 'x')}\n`);
    
    return {
        name,
        origTime,
        jsTime,
        rustTime,
        origTimePerOp,
        jsTimePerOp,
        rustTimePerOp,
        jsSpeedup,
        rustSpeedup,
        iterations
    };
}

// Display result summary
function displaySummary(results) {
    const table = new Table({
        head: [
            colors.cyan('Operation'),
            colors.cyan('JS (jsbn) Time/Op'),
            colors.cyan('JS (BigInt) Time/Op'),
            colors.cyan('Rust Time/Op'),
            colors.cyan('BigInt vs jsbn'),
            colors.cyan('Rust vs jsbn')
        ],
        colWidths: [25, 20, 20, 20, 18, 18]
    });
    
    // Calculate overall average speedup
    let totalJsSpeedup = 0;
    let totalRustSpeedup = 0;
    let operationsCount = 0;
    
    for (const key in results) {
        const result = results[key];
        
        table.push([
            result.name,
            result.origTimePerOp.toFixed(3) + ' ms',
            result.jsTimePerOp.toFixed(3) + ' ms',
            result.rustTimePerOp.toFixed(3) + ' ms',
            colors.green(result.jsSpeedup.toFixed(2) + 'x'),
            colors.green(result.rustSpeedup.toFixed(2) + 'x')
        ]);
        
        totalJsSpeedup += result.jsSpeedup;
        totalRustSpeedup += result.rustSpeedup;
        operationsCount++;
    }
    
    const avgJsSpeedup = totalJsSpeedup / operationsCount;
    const avgRustSpeedup = totalRustSpeedup / operationsCount;
    
    console.log(colors.cyan('=== SRP Performance Benchmark Summary ==='));
    console.log(table.toString());
    console.log(`Average BigInt speedup vs jsbn: ${colors.green(avgJsSpeedup.toFixed(2) + 'x')}`);
    console.log(`Average Rust speedup vs jsbn: ${colors.green(avgRustSpeedup.toFixed(2) + 'x')}`);
    console.log(colors.yellow('\nNote: Higher speedup values indicate better performance compared to the original jsbn implementation.'));
}

// Run benchmark (iterations can be controlled via command line argument)
const iterations = process.argv[2] ? parseInt(process.argv[2], 10) : 100;
runBenchmark(iterations);
