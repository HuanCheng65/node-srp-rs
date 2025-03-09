import test from 'ava';
// 原始 JavaScript 实现
import * as jsSrpClient from '@ruc-cheese/secure-remote-password/client.js';
import * as jsSrpServer from '@ruc-cheese/secure-remote-password/server.js';
// Rust 实现
import { Client as RustSrpClient, Server as RustSrpServer } from '../index.js';

// 初始化 Rust 实现
const rustClient = new RustSrpClient();
const rustServer = new RustSrpServer();

// 测试用户数据
const TEST_USERNAME = 'test_user@example.com';
const TEST_PASSWORD = 'secure_password123!';

// 比较两个十六进制字符串（忽略大小写）
function compareHex(t, actual, expected, message) {
  t.is(
    actual.toLowerCase().replace(/^0+/, ''),
    expected.toLowerCase().replace(/^0+/, ''),
    message
  );
}

// 测试 Salt 生成
test('Salt generation should have correct format', t => {
  const jsSalt = jsSrpClient.generateSalt();
  const rustSalt = rustClient.generateSalt();
  
  t.is(typeof jsSalt, 'string', 'JS salt should be a string');
  t.is(typeof rustSalt, 'string', 'Rust salt should be a string');
  t.regex(jsSalt, /^[0-9a-f]+$/i, 'JS salt should be a hex string');
  t.regex(rustSalt, /^[0-9a-f]+$/i, 'Rust salt should be a hex string');
});

// 测试私钥派生
test('Private key derivation should match', t => {
  const salt = jsSrpClient.generateSalt();
  
  const jsPrivateKey = jsSrpClient.derivePrivateKey(salt, TEST_USERNAME, TEST_PASSWORD);
  const rustPrivateKey = rustClient.derivePrivateKey(salt, TEST_USERNAME, TEST_PASSWORD);
  
  compareHex(t, rustPrivateKey, jsPrivateKey, 'Private keys should match');
});

// 测试验证器生成
test('Verifier generation should match', t => {
  const salt = jsSrpClient.generateSalt();
  const privateKey = jsSrpClient.derivePrivateKey(salt, TEST_USERNAME, TEST_PASSWORD);
  
  const jsVerifier = jsSrpClient.deriveVerifier(privateKey);
  const rustVerifier = rustClient.deriveVerifier(privateKey);
  
  compareHex(t, rustVerifier, jsVerifier, 'Verifiers should match');
});

// 测试客户端临时密钥结构匹配
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

// 测试服务器临时密钥生成
test('Server ephemeral key generation should match', t => {
  const salt = jsSrpClient.generateSalt();
  const privateKey = jsSrpClient.derivePrivateKey(salt, TEST_USERNAME, TEST_PASSWORD);
  const verifier = jsSrpClient.deriveVerifier(privateKey);
  
  const jsServerEphemeral = jsSrpServer.generateEphemeral(verifier);
  const rustServerEphemeral = rustServer.generateEphemeral(verifier);
  
  t.true('secret' in jsServerEphemeral && 'public' in jsServerEphemeral, 'JS server ephemeral has correct structure');
  t.true('secret' in rustServerEphemeral && 'public' in rustServerEphemeral, 'Rust server ephemeral has correct structure');
});

// 测试完整的 SRP 验证流程
test('Complete SRP authentication flow should succeed', async t => {
  // 1. 初始注册阶段
  const salt = jsSrpClient.generateSalt();
  const privateKey = jsSrpClient.derivePrivateKey(salt, TEST_USERNAME, TEST_PASSWORD);
  const verifier = jsSrpClient.deriveVerifier(privateKey);
  
  // 2. 认证阶段 - 使用 Rust 实现客户端，JS 实现服务端
  const clientEphemeral = rustClient.generateEphemeral();
  const serverEphemeral = jsSrpServer.generateEphemeral(verifier);
  
  // 3. 客户端计算会话密钥和证明
  const clientSession = rustClient.deriveSession(
    clientEphemeral.secret,
    serverEphemeral.public,
    salt,
    TEST_USERNAME,
    privateKey
  );
  
  // 4. 服务端计算会话密钥和证明
  const serverSession = jsSrpServer.deriveSession(
    serverEphemeral.secret,
    clientEphemeral.public,
    salt,
    TEST_USERNAME,
    verifier,
    clientSession.proof
  );
  
  // 5. 客户端验证服务端的证明
  t.notThrows(() => {
    rustClient.verifySession(
      clientEphemeral.public,
      clientSession,
      serverSession.proof
    );
  }, 'Client should verify server proof successfully');
  
  // 6. 确保密钥匹配
  compareHex(t, clientSession.key, serverSession.key, 'Session keys should match');
});

// 测试完整的 SRP 验证流程（反向：JS 客户端，Rust 服务端）
test('Complete SRP authentication flow should succeed (reverse)', async t => {
  // 1. 初始注册阶段
  const salt = jsSrpClient.generateSalt();
  const privateKey = jsSrpClient.derivePrivateKey(salt, TEST_USERNAME, TEST_PASSWORD);
  const verifier = jsSrpClient.deriveVerifier(privateKey);
  
  // 2. 认证阶段 - 使用 JS 实现客户端，Rust 实现服务端
  const clientEphemeral = jsSrpClient.generateEphemeral();
  const serverEphemeral = rustServer.generateEphemeral(verifier);
  
  // 3. 客户端计算会话密钥和证明
  const clientSession = jsSrpClient.deriveSession(
    clientEphemeral.secret,
    serverEphemeral.public,
    salt,
    TEST_USERNAME,
    privateKey
  );
  
  // 4. 服务端计算会话密钥和证明
  const serverSession = rustServer.deriveSession(
    serverEphemeral.secret,
    clientEphemeral.public,
    salt,
    TEST_USERNAME,
    verifier,
    clientSession.proof
  );
  
  // 5. 客户端验证服务端的证明
  t.notThrows(() => {
    jsSrpClient.verifySession(
      clientEphemeral.public,
      clientSession,
      serverSession.proof
    );
  }, 'Client should verify server proof successfully');
  
  // 6. 确保密钥匹配
  compareHex(t, clientSession.key, serverSession.key, 'Session keys should match');
});

// 交叉验证测试：使用混合实现
test('Cross-implementation SRP authentication should work', async t => {
  // 1. 初始注册阶段
  const salt = rustClient.generateSalt();
  const privateKey = rustClient.derivePrivateKey(salt, TEST_USERNAME, TEST_PASSWORD);
  const verifier = rustClient.deriveVerifier(privateKey);
  
  // 2. 客户端（JS）和服务端（Rust）阶段
  const clientEphemeral = jsSrpClient.generateEphemeral();
  const serverEphemeral = rustServer.generateEphemeral(verifier);
  
  // 3. 客户端计算会话密钥和证明
  const clientSession = jsSrpClient.deriveSession(
    clientEphemeral.secret,
    serverEphemeral.public,
    salt,
    TEST_USERNAME,
    privateKey,
    clientEphemeral.public
  );
  
  // 4. 服务端计算会话密钥和证明
  const serverSession = rustServer.deriveSession(
    serverEphemeral.secret,
    clientEphemeral.public,
    salt,
    TEST_USERNAME,
    verifier,
    clientSession.proof
  );
  
  // 5. 客户端验证服务端的证明
  t.notThrows(() => {
    jsSrpClient.verifySession(
      clientEphemeral.public,
      clientSession,
      serverSession.proof
    );
  }, 'JS client should verify Rust server proof');
  
  // 6. 交叉验证（Rust 客户端验证 JS 服务端，反之亦然）
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

// 错误处理测试：无效的服务端临时值
test('Invalid server ephemeral should be rejected', t => {
  const salt = jsSrpClient.generateSalt();
  const privateKey = jsSrpClient.derivePrivateKey(salt, TEST_USERNAME, TEST_PASSWORD);
  const clientEphemeral = rustClient.generateEphemeral();
  
  // 零值应该被拒绝
  const error = t.throws(() => {
    rustClient.deriveSession(
      clientEphemeral.secret,
      '0', // 无效的服务端临时公钥
      salt,
      TEST_USERNAME,
      privateKey
    );
  });
  
  t.is(error.message, 'The server sent an invalid public ephemeral');
});

// 错误处理测试：无效的客户端证明
test('Invalid client proof should be rejected', t => {
  const salt = jsSrpClient.generateSalt();
  const privateKey = jsSrpClient.derivePrivateKey(salt, TEST_USERNAME, TEST_PASSWORD);
  const verifier = jsSrpClient.deriveVerifier(privateKey);
  
  const clientEphemeral = rustClient.generateEphemeral();
  const serverEphemeral = rustServer.generateEphemeral(verifier);
  
  const invalidProof = 'abcdef1234567890'; // 无效的客户端证明
  
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
  
  t.is(error.message, 'Client provided session proof is invalid');
});
