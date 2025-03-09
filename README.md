# @ruc-cheese/node-srp-rs

A high-performance Secure Remote Password (SRP-6a) protocol implementation for Node.js, powered by Rust.

[![npm version](https://img.shields.io/npm/v/@ruc-cheese/node-srp-rs.svg)](https://www.npmjs.com/package/@ruc-cheese/node-srp-rs)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

## Overview

This library provides a blazing-fast implementation of the Secure Remote Password (SRP-6a) protocol using Rust with N-API bindings for Node.js.

SRP is a password-authenticated key exchange protocol that allows secure authentication without sending passwords over the network.

## Features

- 🚀 **High Performance**: Up to 15x faster than JavaScript implementations
- 🔒 **Full SRP-6a Protocol**: Complete implementation of the SRP-6a protocol
- 💻 **Native Node.js Bindings**: Seamless integration with Node.js applications
- 🔄 **API Compatible**: Drop-in replacement for `secure-remote-password`
- 🧪 **Thoroughly Tested**: Comprehensive test suite ensures correctness

## Installation

Install using your preferred package manager:

```bash
# npm
npm install @ruc-cheese/node-srp-rs

# yarn
yarn add @ruc-cheese/node-srp-rs

# pnpm
pnpm add @ruc-cheese/node-srp-rs
```

## Usage

### ESM (Recommended)

```javascript
import { Client, Server } from '@ruc-cheese/node-srp-rs';

// Create client and server instances
const client = new Client();
const server = new Server();

// Registration phase
const salt = client.generateSalt();
const privateKey = client.derivePrivateKey(salt, username, password);
const verifier = client.deriveVerifier(privateKey);

// Store salt and verifier on server
// ...

// Authentication phase
// 1. Client generates ephemeral key pair
const clientEphemeral = client.generateEphemeral();

// 2. Server generates ephemeral key pair using stored verifier
const serverEphemeral = server.generateEphemeral(verifier);

// 3. Client computes session and proof
const clientSession = client.deriveSession(
  clientEphemeral.secret,
  serverEphemeral.public,
  salt,
  username,
  privateKey
);

// 4. Server verifies client proof and generates server proof
const serverSession = server.deriveSession(
  serverEphemeral.secret,
  clientEphemeral.public,
  salt,
  username,
  verifier,
  clientSession.proof
);

// 5. Client verifies server proof
client.verifySession(
  clientEphemeral.public,
  clientSession,
  serverSession.proof
);

// Both client and server now have matching session keys
console.log(clientSession.key === serverSession.key); // true
```

### CommonJS

```javascript
const { Client, Server } = require('@ruc-cheese/node-srp-rs');

// Same usage as above
```

## API Reference

### Client

- `client.generateSalt()`: Generates a random salt for password hashing
- `client.derivePrivateKey(salt, username, password)`: Derives private key from credentials
- `client.deriveVerifier(privateKey)`: Generates a password verifier from private key
- `client.generateEphemeral()`: Creates client ephemeral key pair
- `client.deriveSession(secret, serverPublic, salt, username, privateKey)`: Computes session key and proof
- `client.verifySession(clientPublic, clientSession, serverProof)`: Verifies server session proof

### Server

- `server.generateEphemeral(verifier)`: Creates server ephemeral key pair
- `server.deriveSession(secret, clientPublic, salt, username, verifier, clientProof)`: Verifies client proof and generates server proof

## Performance

This Rust implementation significantly outperforms JavaScript SRP implementations:

### Benchmark Results

| Operation | JS (jsbn) Time/Op | JS (BigInt) Time/Op | Rust Time/Op | BigInt vs jsbn | Rust vs jsbn |
|-----------|-------------------|---------------------|--------------|----------------|--------------|
| Salt Generation | 0.013 ms | 0.006 ms | 0.001 ms | 2.07x | 10.60x |
| Private Key Derivation | 0.015 ms | 0.009 ms | 0.003 ms | 1.55x | 5.14x |
| Verifier Generation | 8.890 ms | 2.217 ms | 0.575 ms | 4.01x | 15.45x |
| Client Ephemeral Generation | 9.221 ms | 2.600 ms | 0.654 ms | 3.55x | 14.11x |
| Server Ephemeral Generation | 9.063 ms | 2.238 ms | 0.730 ms | 4.05x | 12.41x |
| Client Session Derivation | 36.613 ms | 9.382 ms | 2.638 ms | 3.90x | 13.88x |
| Server Session Derivation | 27.177 ms | 6.852 ms | 1.855 ms | 3.97x | 14.65x |
| Complete Authentication Flow | 84.076 ms | 19.956 ms | 5.273 ms | 4.21x | 15.95x |

**Implementation Comparison:**
- **JS (jsbn)**: Original JavaScript implementation using the jsbn library for BigInt operations
- **JS (BigInt)**: Improved JavaScript implementation using native BigInt in Node.js
- **Rust**: This library's Rust implementation with NAPI bindings

The Rust implementation is on average **12.77x faster** than the original JavaScript implementation and **3.75x faster** than the BigInt-based JavaScript implementation.

## License

MIT

## Acknowledgements

- Based on the work of [secure-remote-password](https://github.com/LinusU/secure-remote-password)

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
