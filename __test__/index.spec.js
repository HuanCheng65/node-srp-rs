import test from 'ava';
// Original JavaScript implementation
import * as jsSrpClient from '@ruc-cheese/secure-remote-password/client.js';
import * as jsSrpServer from '@ruc-cheese/secure-remote-password/server.js';
// Rust implementation
import { Client as RustSrpClient, Server as RustSrpServer, SrpGroup, srpGroupFromValue } from '../index.js';
import crypto from 'crypto';

// Initialize Rust implementation
const rustClient = new RustSrpClient();
const rustServer = new RustSrpServer();

// Test user data
const TEST_USERNAME = 'test_user@example.com';
const TEST_PASSWORD = 'secure_password123!';

// Compare two hex strings (case-insensitive)
function compareHex(t, actual, expected, message) {
  t.is(
    actual.toLowerCase().replace(/^0+/, ''),
    expected.toLowerCase().replace(/^0+/, ''),
    message
  );
}

// Generate random username and password
function generateRandomCredentials() {
  const randomId = crypto.randomBytes(8).toString('hex');
  return {
    username: `user_${randomId}@example.com`,
    password: `pass_${crypto.randomBytes(12).toString('hex')}`
  };
}

// Perform a complete SRP authentication cycle
function performSRPAuthentication(t, client, server, username, password) {
  // 1. Registration phase
  const salt = client.generateSalt();
  const privateKey = client.derivePrivateKey(salt, username, password);
  const verifier = client.deriveVerifier(privateKey);
  
  // 2. Authentication phase
  const clientEphemeral = client.generateEphemeral();
  const serverEphemeral = server.generateEphemeral(verifier);
  
  const clientSession = client.deriveSession(
    clientEphemeral.secret,
    serverEphemeral.public,
    salt,
    username,
    privateKey
  );
  
  const serverSession = server.deriveSession(
    serverEphemeral.secret,
    clientEphemeral.public,
    salt,
    username,
    verifier,
    clientSession.proof
  );
  
  t.notThrows(() => {
    client.verifySession(
      clientEphemeral.public,
      clientSession,
      serverSession.proof
    );
  }, 'Client should verify server proof successfully');
  
  compareHex(t, clientSession.key, serverSession.key, 'Session keys should match');
  
  return { clientSession, serverSession };
}

test('Salt generation should have correct format', t => {
  const jsSalt = jsSrpClient.generateSalt();
  const rustSalt = rustClient.generateSalt();
  
  t.is(typeof jsSalt, 'string', 'JS salt should be a string');
  t.is(typeof rustSalt, 'string', 'Rust salt should be a string');
  t.regex(jsSalt, /^[0-9a-f]+$/i, 'JS salt should be a hex string');
  t.regex(rustSalt, /^[0-9a-f]+$/i, 'Rust salt should be a hex string');
});

test('Private key derivation should match', t => {
  const salt = jsSrpClient.generateSalt();
  
  const jsPrivateKey = jsSrpClient.derivePrivateKey(salt, TEST_USERNAME, TEST_PASSWORD);
  const rustPrivateKey = rustClient.derivePrivateKey(salt, TEST_USERNAME, TEST_PASSWORD);
  
  compareHex(t, rustPrivateKey, jsPrivateKey, 'Private keys should match');
});

test('Verifier generation should match', t => {
  const salt = jsSrpClient.generateSalt();
  const privateKey = jsSrpClient.derivePrivateKey(salt, TEST_USERNAME, TEST_PASSWORD);
  
  const jsVerifier = jsSrpClient.deriveVerifier(privateKey);
  const rustVerifier = rustClient.deriveVerifier(privateKey);
  
  compareHex(t, rustVerifier, jsVerifier, 'Verifiers should match');
});

test('Client ephemeral key structure should match', t => {
  const jsEphemeral = jsSrpClient.generateEphemeral();
  const rustEphemeral = rustClient.generateEphemeral();
  
  t.true('secret' in jsEphemeral && 'public' in jsEphemeral, 'JS ephemeral has correct structure');
  t.true('secret' in rustEphemeral && 'public' in rustEphemeral, 'Rust ephemeral has correct structure');
  
  t.is(typeof jsEphemeral.secret, 'string', 'JS ephemeral secret is a string');
  t.is(typeof jsEphemeral.public, 'string', 'JS ephemeral public is a string');
  t.is(typeof rustEphemeral.secret, 'string', 'Rust ephemeral secret is a string');
  t.is(typeof rustEphemeral.public, 'string', 'Rust ephemeral public is a string');
});

test('Server ephemeral key generation should match', t => {
  const salt = jsSrpClient.generateSalt();
  const privateKey = jsSrpClient.derivePrivateKey(salt, TEST_USERNAME, TEST_PASSWORD);
  const verifier = jsSrpClient.deriveVerifier(privateKey);
  
  const jsServerEphemeral = jsSrpServer.generateEphemeral(verifier);
  const rustServerEphemeral = rustServer.generateEphemeral(verifier);
  
  t.true('secret' in jsServerEphemeral && 'public' in jsServerEphemeral, 'JS server ephemeral has correct structure');
  t.true('secret' in rustServerEphemeral && 'public' in rustServerEphemeral, 'Rust server ephemeral has correct structure');
});

test('Complete SRP authentication flow should succeed', async t => {
  // Registration phase
  const salt = jsSrpClient.generateSalt();
  const privateKey = jsSrpClient.derivePrivateKey(salt, TEST_USERNAME, TEST_PASSWORD);
  const verifier = jsSrpClient.deriveVerifier(privateKey);
  
  // Authentication phase - Rust client, JS server
  const clientEphemeral = rustClient.generateEphemeral();
  const serverEphemeral = jsSrpServer.generateEphemeral(verifier);
  
  const clientSession = rustClient.deriveSession(
    clientEphemeral.secret,
    serverEphemeral.public,
    salt,
    TEST_USERNAME,
    privateKey
  );
  
  const serverSession = jsSrpServer.deriveSession(
    serverEphemeral.secret,
    clientEphemeral.public,
    salt,
    TEST_USERNAME,
    verifier,
    clientSession.proof
  );
  
  t.notThrows(() => {
    rustClient.verifySession(
      clientEphemeral.public,
      clientSession,
      serverSession.proof
    );
  }, 'Client should verify server proof successfully');
  
  compareHex(t, clientSession.key, serverSession.key, 'Session keys should match');
});

test('Complete SRP authentication flow should succeed (reverse)', async t => {
  // Registration phase
  const salt = jsSrpClient.generateSalt();
  const privateKey = jsSrpClient.derivePrivateKey(salt, TEST_USERNAME, TEST_PASSWORD);
  const verifier = jsSrpClient.deriveVerifier(privateKey);
  
  // Authentication phase - JS client, Rust server
  const clientEphemeral = jsSrpClient.generateEphemeral();
  const serverEphemeral = rustServer.generateEphemeral(verifier);
  
  const clientSession = jsSrpClient.deriveSession(
    clientEphemeral.secret,
    serverEphemeral.public,
    salt,
    TEST_USERNAME,
    privateKey
  );
  
  const serverSession = rustServer.deriveSession(
    serverEphemeral.secret,
    clientEphemeral.public,
    salt,
    TEST_USERNAME,
    verifier,
    clientSession.proof
  );
  
  t.notThrows(() => {
    jsSrpClient.verifySession(
      clientEphemeral.public,
      clientSession,
      serverSession.proof
    );
  }, 'Client should verify server proof successfully');
  
  compareHex(t, clientSession.key, serverSession.key, 'Session keys should match');
});

test('Cross-implementation SRP authentication should work', async t => {
  // Registration phase
  const salt = rustClient.generateSalt();
  const privateKey = rustClient.derivePrivateKey(salt, TEST_USERNAME, TEST_PASSWORD);
  const verifier = rustClient.deriveVerifier(privateKey);
  
  // Client (JS) and server (Rust) phase
  const clientEphemeral = jsSrpClient.generateEphemeral();
  const serverEphemeral = rustServer.generateEphemeral(verifier);
  
  const clientSession = jsSrpClient.deriveSession(
    clientEphemeral.secret,
    serverEphemeral.public,
    salt,
    TEST_USERNAME,
    privateKey,
    clientEphemeral.public
  );
  
  const serverSession = rustServer.deriveSession(
    serverEphemeral.secret,
    clientEphemeral.public,
    salt,
    TEST_USERNAME,
    verifier,
    clientSession.proof
  );
  
  t.notThrows(() => {
    jsSrpClient.verifySession(
      clientEphemeral.public,
      clientSession,
      serverSession.proof
    );
  }, 'JS client should verify Rust server proof');
  
  // Cross validation (Rust client verifies JS server and vice versa)
  const rustClientEphemeral = rustClient.generateEphemeral();
  const jsServerEphemeral = jsSrpServer.generateEphemeral(verifier);
  
  const rustClientSession = rustClient.deriveSession(
    rustClientEphemeral.secret,
    jsServerEphemeral.public,
    salt, 
    TEST_USERNAME,
    privateKey
  );
  
  const jsServerSession = jsSrpServer.deriveSession(
    jsServerEphemeral.secret,
    rustClientEphemeral.public,
    salt,
    TEST_USERNAME,
    verifier,
    rustClientSession.proof
  );
  
  t.notThrows(() => {
    rustClient.verifySession(
      rustClientEphemeral.public,
      rustClientSession,
      jsServerSession.proof
    );
  }, 'Rust client should verify JS server proof');
});

test('Invalid server ephemeral should be rejected', t => {
  const salt = jsSrpClient.generateSalt();
  const privateKey = jsSrpClient.derivePrivateKey(salt, TEST_USERNAME, TEST_PASSWORD);
  const clientEphemeral = rustClient.generateEphemeral();
  
  // Zero value should be rejected
  const error = t.throws(() => {
    rustClient.deriveSession(
      clientEphemeral.secret,
      '0', // Invalid server ephemeral public key
      salt,
      TEST_USERNAME,
      privateKey
    );
  });
  
  t.is(error.message, 'Server\'s public ephemeral value is invalid');
});

test('Invalid client proof should be rejected', t => {
  const salt = jsSrpClient.generateSalt();
  const privateKey = jsSrpClient.derivePrivateKey(salt, TEST_USERNAME, TEST_PASSWORD);
  const verifier = jsSrpClient.deriveVerifier(privateKey);
  
  const clientEphemeral = rustClient.generateEphemeral();
  const serverEphemeral = rustServer.generateEphemeral(verifier);
  
  const invalidProof = 'abcdef1234567890'; // Invalid client proof
  
  const error = t.throws(() => {
    rustServer.deriveSession(
      serverEphemeral.secret,
      clientEphemeral.public,
      salt,
      TEST_USERNAME,
      verifier,
      invalidProof
    );
  });
  
  t.is(error.message, 'Client\'s proof is invalid');
});

// ===== Additional SRP parameter group tests =====

test('SRP authentication flow with 1024-bit group', async t => {
  // Create client and server with 1024-bit parameter group
  const client1024 = new RustSrpClient(SrpGroup.RFC5054_1024);
  const server1024 = new RustSrpServer(SrpGroup.RFC5054_1024);
  
  // Registration phase
  const salt = client1024.generateSalt();
  const privateKey = client1024.derivePrivateKey(salt, TEST_USERNAME, TEST_PASSWORD);
  const verifier = client1024.deriveVerifier(privateKey);
  
  const clientEphemeral = client1024.generateEphemeral();
  const serverEphemeral = server1024.generateEphemeral(verifier);
  
  const clientSession = client1024.deriveSession(
    clientEphemeral.secret,
    serverEphemeral.public,
    salt,
    TEST_USERNAME,
    privateKey
  );
  
  const serverSession = server1024.deriveSession(
    serverEphemeral.secret,
    clientEphemeral.public,
    salt,
    TEST_USERNAME,
    verifier,
    clientSession.proof
  );
  
  t.notThrows(() => {
    client1024.verifySession(
      clientEphemeral.public,
      clientSession,
      serverSession.proof
    );
  }, '1024-bit client should verify server proof');
  
  t.is(clientSession.key, serverSession.key, '1024-bit session keys should match');
});

test('SRP authentication flow with 4096-bit group', async t => {
  // Create client and server with 4096-bit parameter group
  const client4096 = new RustSrpClient(SrpGroup.RFC5054_4096);
  const server4096 = new RustSrpServer(SrpGroup.RFC5054_4096);
  
  // Registration phase
  const salt = client4096.generateSalt();
  const privateKey = client4096.derivePrivateKey(salt, TEST_USERNAME, TEST_PASSWORD);
  const verifier = client4096.deriveVerifier(privateKey);
  
  const clientEphemeral = client4096.generateEphemeral();
  const serverEphemeral = server4096.generateEphemeral(verifier);
  
  const clientSession = client4096.deriveSession(
    clientEphemeral.secret,
    serverEphemeral.public,
    salt,
    TEST_USERNAME,
    privateKey
  );
  
  const serverSession = server4096.deriveSession(
    serverEphemeral.secret,
    clientEphemeral.public,
    salt,
    TEST_USERNAME,
    verifier,
    clientSession.proof
  );
  
  t.notThrows(() => {
    client4096.verifySession(
      clientEphemeral.public,
      clientSession,
      serverSession.proof
    );
  }, '4096-bit client should verify server proof');
  
  t.is(clientSession.key, serverSession.key, '4096-bit session keys should match');
});

test('srpGroupFromValue function should create correct group', t => {
  const group1024 = srpGroupFromValue(1024);
  const group1536 = srpGroupFromValue(1536);
  const group2048 = srpGroupFromValue(2048);
  const group3072 = srpGroupFromValue(3072);
  const group4096 = srpGroupFromValue(4096);
  
  t.deepEqual(group1024, SrpGroup.RFC5054_1024, 'Group 1024 created correctly');
  t.deepEqual(group1536, SrpGroup.RFC5054_1536, 'Group 1536 created correctly');
  t.deepEqual(group2048, SrpGroup.RFC5054_2048, 'Group 2048 created correctly');
  t.deepEqual(group3072, SrpGroup.RFC5054_3072, 'Group 3072 created correctly');
  t.deepEqual(group4096, SrpGroup.RFC5054_4096, 'Group 4096 created correctly');
  
  // Test invalid parameters
  t.throws(() => {
    srpGroupFromValue(1000);
  }, { message: /Invalid SRP group size/ }, 'Invalid group size should throw error');
});

test('Mixing different parameter groups should fail', async t => {
  // Create client and server with different parameter groups
  const client1024 = new RustSrpClient(SrpGroup.RFC5054_1024);
  const server4096 = new RustSrpServer(SrpGroup.RFC5054_4096);
  
  // Registration phase
  const salt = client1024.generateSalt();
  const privateKey = client1024.derivePrivateKey(salt, TEST_USERNAME, TEST_PASSWORD);
  const verifier = client1024.deriveVerifier(privateKey);
  
  const clientEphemeral = client1024.generateEphemeral();
  const serverEphemeral = server4096.generateEphemeral(verifier);
  
  // Client tries to calculate session (should fail because server uses different parameter group)
  const clientSession = client1024.deriveSession(
    clientEphemeral.secret,
    serverEphemeral.public,
    salt,
    TEST_USERNAME,
    privateKey
  );
  
  // Server tries to verify client proof (should fail)
  const error = t.throws(() => {
    server4096.deriveSession(
      serverEphemeral.secret,
      clientEphemeral.public,
      salt,
      TEST_USERNAME,
      verifier,
      clientSession.proof
    );
  });
  
  t.regex(error.message, /proof is invalid/, 'Mixing parameter groups should fail validation');
});

test('All five parameter groups should work correctly', async t => {
  const groups = [
    SrpGroup.RFC5054_1024,
    SrpGroup.RFC5054_1536,
    SrpGroup.RFC5054_2048,
    SrpGroup.RFC5054_3072,
    SrpGroup.RFC5054_4096
  ];
  
  for (const group of groups) {
    // Create client and server with specific parameter group
    const client = new RustSrpClient(group);
    const server = new RustSrpServer(group);
    
    // Registration phase
    const salt = client.generateSalt();
    const privateKey = client.derivePrivateKey(salt, TEST_USERNAME, TEST_PASSWORD);
    const verifier = client.deriveVerifier(privateKey);
    
    const clientEphemeral = client.generateEphemeral();
    const serverEphemeral = server.generateEphemeral(verifier);
    
    const clientSession = client.deriveSession(
      clientEphemeral.secret,
      serverEphemeral.public,
      salt,
      TEST_USERNAME,
      privateKey
    );
    
    const serverSession = server.deriveSession(
      serverEphemeral.secret,
      clientEphemeral.public,
      salt,
      TEST_USERNAME,
      verifier,
      clientSession.proof
    );
    
    t.is(clientSession.key, serverSession.key, `Session keys should match for group ${group}`);
  }
});

// ==================== Additional stress tests ====================

test('Stress test: Multiple authentication cycles should succeed', async t => {
  const ITERATIONS = 100; // Repeat 100 times
  
  for (let i = 0; i < ITERATIONS; i++) {
    // Using Rust client and JS server
    const salt = rustClient.generateSalt();
    const privateKey = rustClient.derivePrivateKey(salt, TEST_USERNAME, TEST_PASSWORD);
    const verifier = rustClient.deriveVerifier(privateKey);
    
    const clientEphemeral = rustClient.generateEphemeral();
    const serverEphemeral = jsSrpServer.generateEphemeral(verifier);
    
    const clientSession = rustClient.deriveSession(
      clientEphemeral.secret,
      serverEphemeral.public,
      salt,
      TEST_USERNAME,
      privateKey
    );
    
    const serverSession = jsSrpServer.deriveSession(
      serverEphemeral.secret,
      clientEphemeral.public,
      salt,
      TEST_USERNAME,
      verifier,
      clientSession.proof
    );
    
    t.notThrows(() => {
      rustClient.verifySession(
        clientEphemeral.public,
        clientSession,
        serverSession.proof
      );
    }, `Iteration ${i+1}: Client should verify server proof successfully`);
    
    compareHex(t, clientSession.key, serverSession.key, `Iteration ${i+1}: Session keys should match`);
    
    // Using JS client and Rust server
    const jsClientEphemeral = jsSrpClient.generateEphemeral();
    const rustServerEphemeral = rustServer.generateEphemeral(verifier);
    
    const jsClientSession = jsSrpClient.deriveSession(
      jsClientEphemeral.secret,
      rustServerEphemeral.public,
      salt,
      TEST_USERNAME,
      privateKey
    );
    
    const rustServerSession = rustServer.deriveSession(
      rustServerEphemeral.secret,
      jsClientEphemeral.public,
      salt,
      TEST_USERNAME,
      verifier,
      jsClientSession.proof
    );
    
    t.notThrows(() => {
      jsSrpClient.verifySession(
        jsClientEphemeral.public,
        jsClientSession,
        rustServerSession.proof
      );
    }, `Iteration ${i+1}: JS client should verify Rust server proof`);
    
    compareHex(t, jsClientSession.key, rustServerSession.key, `Iteration ${i+1}: JS-Rust session keys should match`);
  }
});

test('Random credentials: Authentication should work with different usernames and passwords', async t => {
  const CREDENTIALS_COUNT = 20; // Test 20 different credential sets
  
  for (let i = 0; i < CREDENTIALS_COUNT; i++) {
    const { username, password } = generateRandomCredentials();
    
    // Rust client, JS server
    performSRPAuthentication(t, rustClient, jsSrpServer, username, password);
    
    // JS client, Rust server
    performSRPAuthentication(t, jsSrpClient, rustServer, username, password);
  }
});

test('Edge cases: Authentication should work with special characters and extreme lengths', async t => {
  const edgeCases = [
    { username: '!@#$%^&*()', password: '!@#$%^&*()_+<>?:"{}|' },
    { username: 'a'.repeat(1), password: 'b'.repeat(1) },
    { username: 'c'.repeat(100), password: 'd'.repeat(100) },
    { username: '🔒🔑🔐', password: '🔒🔑🔐🔓' },
    { username: '用户名', password: '密码' },
    { username: '', password: 'onlypassword' },
    { username: 'onlyusername', password: '' },
    { username: ' spacedusername ', password: ' spacedpassword ' }
  ];
  
  for (const { username, password } of edgeCases) {
    try {
      // Rust client, JS server
      performSRPAuthentication(t, rustClient, jsSrpServer, username, password);
      
      // JS client, Rust server
      performSRPAuthentication(t, jsSrpClient, rustServer, username, password);
    } catch (error) {
      // Log failed cases for debugging
      t.fail(`Failed with username: "${username}", password: "${password}", error: ${error.message}`);
    }
  }
});

test('Concurrent authentication: Multiple flows should succeed in parallel', async t => {
  const CONCURRENT_FLOWS = 10;
  const authPromises = [];
  
  // Set up user credentials
  const credentials = Array.from({ length: CONCURRENT_FLOWS }, () => 
    generateRandomCredentials()
  );
  
  // Precompute all salts and verifiers
  const precomputedData = credentials.map(({ username, password }) => {
    const salt = rustClient.generateSalt();
    const privateKey = rustClient.derivePrivateKey(salt, username, password);
    const verifier = rustClient.deriveVerifier(privateKey);
    return { salt, privateKey, verifier, username, password };
  });
  
  // Create concurrent authentication flows
  for (let i = 0; i < CONCURRENT_FLOWS; i++) {
    const { salt, privateKey, verifier, username, password } = precomputedData[i];
    
    // Each concurrent flow alternates between JS and Rust implementations
    const client = i % 2 === 0 ? rustClient : jsSrpClient;
    const server = i % 2 === 0 ? jsSrpServer : rustServer;
    
    const authPromise = new Promise(resolve => {
      // Create ephemeral keys
      const clientEphemeral = client.generateEphemeral();
      const serverEphemeral = server.generateEphemeral(verifier);
      
      const clientSession = client.deriveSession(
        clientEphemeral.secret,
        serverEphemeral.public,
        salt,
        username,
        privateKey
      );
      
      const serverSession = server.deriveSession(
        serverEphemeral.secret,
        clientEphemeral.public,
        salt,
        username,
        verifier,
        clientSession.proof
      );
      
      client.verifySession(
        clientEphemeral.public,
        clientSession,
        serverSession.proof
      );
      
      resolve({
        clientSession,
        serverSession,
        index: i
      });
    });
    
    authPromises.push(authPromise);
  }
  
  // Wait for all concurrent verifications to complete
  const results = await Promise.all(authPromises);
  
  // Verify results
  for (const { clientSession, serverSession, index } of results) {
    compareHex(t, clientSession.key, serverSession.key, `Concurrent flow ${index}: Session keys should match`);
  }
});
