import * as jsSrp from '@ruc-cheese/secure-remote-password/client.js';
import * as jsSrpServer from '@ruc-cheese/secure-remote-password/server.js';
import { Client, Server } from './index.js';

const rustClient = new Client();

// 测试用户数据
const TEST_USERNAME = 'test_user@example.com';
const TEST_PASSWORD = 'secure_password123!';

// 创建共享参数
const salt = jsSrp.generateSalt();
console.log("Salt:", salt);

const jsPrivateKey = jsSrp.derivePrivateKey(salt, TEST_USERNAME, TEST_PASSWORD);
const rustPrivateKey = rustClient.derivePrivateKey(salt, TEST_USERNAME, TEST_PASSWORD);
console.log("JS Private Key:", jsPrivateKey);
console.log("Rust Private Key:", rustPrivateKey);

const jsVerifier = jsSrp.deriveVerifier(jsPrivateKey);
const rustVerifier = rustClient.deriveVerifier(rustPrivateKey);
console.log("JS Verifier:", jsVerifier);
console.log("Rust Verifier:", rustVerifier);

// 创建临时密钥
const jsClientEphemeral = jsSrp.generateEphemeral();
const jsServerEphemeral = jsSrpServer.generateEphemeral(jsVerifier);
console.log("JS Client Public:", jsClientEphemeral.public);
console.log("JS Server Public:", jsServerEphemeral.public);

// 跟踪每一步计算
const jsClientSession = jsSrp.deriveSession(
  jsClientEphemeral.secret,
  jsServerEphemeral.public,
  salt,
  TEST_USERNAME,
  jsPrivateKey
);

const rustClientSession = rustClient.deriveSession(
  jsClientEphemeral.secret,
  jsServerEphemeral.public,
  salt,
  TEST_USERNAME,
  jsPrivateKey
);

console.log("JS Client Proof:", jsClientSession.proof);
console.log("Rust Client Proof:", rustClientSession.proof);
