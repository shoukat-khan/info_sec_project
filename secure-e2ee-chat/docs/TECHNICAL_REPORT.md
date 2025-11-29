# Secure End-to-End Encrypted Chat Application
## Technical Report & Developer Documentation

**Version:** 1.0  
**Date:** 2024  
**Project:** Information Security Semester Project  
**Stack:** MERN (MongoDB, Express.js, React.js, Node.js)  
**Cryptography:** Web Crypto API (SubtleCrypto)

---

## Table of Contents

1. [System Overview](#system-overview)
2. [Architecture](#architecture)
3. [Project Structure](#project-structure)
4. [Phase-by-Phase Implementation](#phase-by-phase-implementation)
5. [Security Features](#security-features)
6. [File Locations & Responsibilities](#file-locations--responsibilities)
7. [Protocol Flow](#protocol-flow)
8. [API Endpoints](#api-endpoints)
9. [Cryptographic Operations](#cryptographic-operations)
10. [Development Guide](#development-guide)

---

## System Overview

This is a secure end-to-end encrypted chat application that implements industry-standard cryptographic protocols to ensure message confidentiality, integrity, and authenticity. The system uses client-side encryption exclusively, ensuring that the server never has access to plaintext messages, files, or private keys.

### Key Features

- **Identity-Based Authentication**: RSA-PSS 2048-bit or ECC P-256 identity keys
- **ECDH Key Exchange**: Ephemeral key exchange with digital signatures
- **End-to-End Encryption**: AES-256-GCM for messages and files
- **Replay Protection**: Multi-layered protection using nonces, timestamps, and sequence numbers
- **Secure File Sharing**: Encrypted file transfer with key wrapping
- **Audit Logging**: Comprehensive security event tracking
- **MITM Attack Demonstration**: Educational demo showing protocol security

---

## Architecture

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        CLIENT (React)                        │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │   Auth       │  │   Key        │  │   Crypto     │      │
│  │   Context    │  │   Exchange   │  │   Utils      │      │
│  │              │  │   Context    │  │              │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
│         │                 │                   │              │
│         └─────────────────┼───────────────────┘              │
│                           │                                  │
│                    ┌──────▼──────┐                           │
│                    │  API Service │                           │
│                    └──────┬──────┘                           │
└───────────────────────────┼──────────────────────────────────┘
                            │ HTTPS
┌───────────────────────────▼──────────────────────────────────┐
│                    SERVER (Express.js)                        │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │   Auth       │  │   Key        │  │   Message    │      │
│  │   Routes     │  │   Exchange   │  │   Routes     │      │
│  │              │  │   Routes     │  │              │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
│         │                 │                   │              │
│         └─────────────────┼───────────────────┘              │
│                           │                                  │
│                    ┌──────▼──────┐                           │
│                    │  Controllers │                           │
│                    └──────┬──────┘                           │
│                           │                                  │
│                    ┌──────▼──────┐                           │
│                    │   MongoDB    │                           │
│                    │  (Mailbox)   │                           │
│                    └─────────────┘                           │
└──────────────────────────────────────────────────────────────┘
```

### Security Model

- **Client-Side Only Cryptography**: All encryption/decryption happens in the browser
- **Server as Mailbox**: Backend only stores and forwards encrypted data
- **Zero-Knowledge Architecture**: Server cannot decrypt any user data
- **Private Keys Never Leave Client**: Stored encrypted in IndexedDB

---

## Project Structure

```
secure-e2ee-chat/
├── client/                          # React Frontend
│   ├── src/
│   │   ├── components/              # Reusable UI components
│   │   │   └── Navbar.jsx          # Navigation bar
│   │   ├── context/                 # React Context providers
│   │   │   ├── AuthContext.jsx     # Authentication state
│   │   │   └── KeyExchangeContext.jsx  # Key exchange & messaging state
│   │   ├── pages/                   # Page components
│   │   │   ├── Login.jsx           # Login page
│   │   │   ├── Register.jsx        # Registration page
│   │   │   ├── Dashboard.jsx       # Main dashboard
│   │   │   └── MitmDemo.jsx        # MITM attack demonstration
│   │   ├── services/                # API communication
│   │   │   └── apiService.js       # Axios instance & API calls
│   │   ├── utils/                   # Utility functions
│   │   │   ├── cryptoUtils.js      # Web Crypto API wrappers
│   │   │   ├── indexedDBUtils.js   # IndexedDB operations
│   │   │   └── mitmDemoUtils.js    # MITM demo utilities
│   │   ├── App.jsx                 # Main app component
│   │   ├── main.jsx                # React entry point
│   │   └── styles.css              # Global styles
│   ├── package.json
│   └── vite.config.js
│
├── server/                          # Express.js Backend
│   ├── src/
│   │   ├── config/
│   │   │   └── db.js               # MongoDB connection
│   │   ├── controllers/             # Request handlers
│   │   │   ├── authController.js   # Authentication logic
│   │   │   ├── keyExchangeController.js  # Key exchange logic
│   │   │   ├── messageController.js      # Message handling
│   │   │   ├── fileController.js         # File operations
│   │   │   └── auditController.js        # Audit logging
│   │   ├── models/                  # Mongoose schemas
│   │   │   ├── User.js             # User model
│   │   │   ├── KeyExchangeRequest.js
│   │   │   ├── KeyExchangeResponse.js
│   │   │   ├── KeyExchangeConfirm.js
│   │   │   ├── Message.js          # Encrypted message model
│   │   │   ├── Conversation.js     # Conversation state (replay protection)
│   │   │   ├── FileMessage.js      # Encrypted file model
│   │   │   └── AuditLog.js         # Audit log model
│   │   ├── routes/                  # API routes
│   │   │   ├── authRoutes.js
│   │   │   ├── keyExchangeRoutes.js
│   │   │   ├── messageRoutes.js
│   │   │   ├── fileRoutes.js
│   │   │   └── auditRoutes.js
│   │   ├── middleware/
│   │   │   └── errorHandler.js     # Error handling middleware
│   │   ├── utils/
│   │   │   └── validateInput.js    # Input validation
│   │   └── server.js               # Express app entry point
│   └── package.json
│
└── docs/                            # Documentation
    ├── protocol.md                  # Protocol explanation
    └── TECHNICAL_REPORT.md          # This file
```

---

## Phase-by-Phase Implementation

### Phase 0: Project Skeleton
**Goal:** Create clean MERN project structure

**Files Created:**
- `server/src/server.js` - Express server setup
- `server/src/config/db.js` - MongoDB connection
- `server/src/models/User.js` - User schema
- `server/src/controllers/authController.js` - Placeholder auth logic
- `server/src/routes/authRoutes.js` - Auth routes
- `client/src/App.jsx` - React app structure
- `client/src/pages/Login.jsx`, `Register.jsx`, `Dashboard.jsx` - Placeholder pages
- `client/src/context/AuthContext.jsx` - Auth context setup

**Key Features:**
- Basic Express server with CORS
- MongoDB connection
- React Router setup
- Clean folder structure

---

### Phase 1: Secure Authentication
**Goal:** Implement username/password authentication with password hashing

**Files Modified:**
- `server/src/models/User.js` - Added `publicKey`, `keyAlgorithm` fields
- `server/src/controllers/authController.js` - Implemented bcrypt password hashing
- `server/src/utils/validateInput.js` - Input validation
- `client/src/pages/Register.jsx` - Registration form with confirm password
- `client/src/pages/Login.jsx` - Login form
- `client/src/context/AuthContext.jsx` - Real auth logic
- `client/src/services/apiService.js` - API calls
- `client/src/styles.css` - Bluish theme

**Key Features:**
- bcrypt password hashing (150,000 iterations)
- Username/password validation
- Confirm password field
- Bluish UI theme
- JWT-ready structure (not implemented yet)

**Location:** 
- Backend: `server/src/controllers/authController.js` (lines 1-80)
- Frontend: `client/src/context/AuthContext.jsx` (lines 24-121)

---

### Phase 2: Identity Key Infrastructure
**Goal:** Generate and securely store identity keys

**Files Created:**
- `client/src/utils/cryptoUtils.js` - Cryptographic functions
- `client/src/utils/indexedDBUtils.js` - IndexedDB operations

**Files Modified:**
- `client/src/context/AuthContext.jsx` - Key generation on registration
- `server/src/controllers/authController.js` - Store public keys

**Key Functions:**
- `generateIdentityKeyPair()` - RSA-PSS 2048-bit or ECC P-256
- `exportPublicKeyJWK()` / `exportPrivateKeyJWK()` - Key export
- `deriveKeyFromPassword()` - PBKDF2 (SHA-256, 150,000 iterations)
- `encryptPrivateKeyWithAES()` - AES-256-GCM encryption
- `decryptPrivateKeyWithAES()` - AES-256-GCM decryption
- `storePrivateKey()` / `retrievePrivateKey()` - IndexedDB operations

**Location:**
- Crypto utilities: `client/src/utils/cryptoUtils.js` (lines 22-154)
- IndexedDB: `client/src/utils/indexedDBUtils.js`
- Key generation: `client/src/context/AuthContext.jsx` (lines 30-58)

---

### Phase 3: Custom Key Exchange Protocol
**Goal:** Implement ECDH key exchange with digital signatures

**Files Created:**
- `server/src/models/KeyExchangeRequest.js`
- `server/src/models/KeyExchangeResponse.js`
- `server/src/models/KeyExchangeConfirm.js`
- `server/src/controllers/keyExchangeController.js`
- `server/src/routes/keyExchangeRoutes.js`
- `client/src/context/KeyExchangeContext.jsx`

**Files Modified:**
- `server/src/server.js` - Mount key exchange routes
- `client/src/main.jsx` - Add KeyExchangeProvider
- `client/src/pages/Dashboard.jsx` - Key exchange UI

**Key Functions:**
- `generateECDHKeyPair()` - ECDH P-256 key pair
- `signData()` - Sign with identity private key (RSA-PSS or ECDSA)
- `verifySignature()` - Verify signature with identity public key
- `deriveSharedSecret()` - ECDH shared secret derivation
- `hkdfExtractAndExpand()` - HKDF (SHA-256) for session key
- `importSessionKey()` - Import AES-256-GCM session key
- `encryptWithSessionKey()` / `decryptWithSessionKey()` - Key confirmation

**Protocol Flow:**
1. Initiator generates ECDH key pair, signs public key, sends request
2. Responder verifies signature, generates ECDH key pair, signs, sends response
3. Both derive shared secret via ECDH
4. Both run HKDF to derive 256-bit session key
5. Exchange KEY-CONFIRM-A and KEY-CONFIRM-B messages
6. Session established

**Location:**
- Key exchange logic: `client/src/context/KeyExchangeContext.jsx` (lines 47-316)
- Backend controller: `server/src/controllers/keyExchangeController.js`
- Crypto functions: `client/src/utils/cryptoUtils.js` (lines 156-300)

---

### Phase 4: Replay Protection
**Goal:** Prevent replay attacks on encrypted messages

**Files Created:**
- `server/src/models/Message.js` - Message schema with metadata
- `server/src/models/Conversation.js` - Conversation state tracking
- `server/src/controllers/messageController.js` - Message handling with replay checks
- `server/src/routes/messageRoutes.js` - Message routes

**Files Modified:**
- `client/src/utils/cryptoUtils.js` - Message encryption with metadata
- `client/src/context/KeyExchangeContext.jsx` - Replay protection logic
- `client/src/pages/Dashboard.jsx` - Messaging UI

**Key Functions:**
- `encryptMessageWithMetadata()` - Encrypt with nonce, sequence, timestamp
- `decryptMessageWithMetadata()` - Decrypt and verify metadata
- `sendEncryptedMessage()` - Send with replay protection
- `receiveEncryptedMessage()` - Receive with replay checks

**Replay Protection Layers:**
1. **Nonces**: 16-byte random values, checked for uniqueness
2. **Timestamps**: Unix epoch milliseconds, 30-second tolerance
3. **Sequence Numbers**: Incremental integers per conversation

**Location:**
- Message encryption: `client/src/utils/cryptoUtils.js` (lines 321-379)
- Replay checks: `client/src/context/KeyExchangeContext.jsx` (lines 341-386)
- Backend validation: `server/src/controllers/messageController.js` (lines 35-104)

---

### Phase 5: MITM Attack Demonstration
**Goal:** Demonstrate MITM vulnerability and protection

**Files Created:**
- `client/src/utils/mitmDemoUtils.js` - Insecure ECDH utilities
- `client/src/pages/MitmDemo.jsx` - MITM demo page

**Files Modified:**
- `client/src/App.jsx` - Add `/mitm-demo` route
- `client/src/pages/Dashboard.jsx` - Link to MITM demo

**Key Features:**
- **Insecure Demo**: Shows how unsigned ECDH can be intercepted
- **Secure Demo**: Shows how signatures prevent MITM attacks
- Uses `shoukat_` and `hashim_` as demo users

**Location:**
- Demo page: `client/src/pages/MitmDemo.jsx`
- Demo utilities: `client/src/utils/mitmDemoUtils.js`

---

### Phase 6: Encrypted File Sharing
**Goal:** End-to-end encrypted file transfer

**Files Created:**
- `server/src/models/FileMessage.js` - Encrypted file model
- `server/src/controllers/fileController.js` - File operations
- `server/src/routes/fileRoutes.js` - File routes

**Files Modified:**
- `client/src/utils/cryptoUtils.js` - File encryption functions
- `client/src/context/KeyExchangeContext.jsx` - File sharing logic
- `client/src/pages/Dashboard.jsx` - File sharing UI

**Key Functions:**
- `generateFileKey()` - Generate per-file AES-256-GCM key
- `encryptFileWithKey()` - Encrypt file bytes
- `wrapFileKeyWithSessionKey()` - Encrypt file key with session key
- `unwrapFileKeyWithSessionKey()` - Decrypt file key
- `decryptFileWithKey()` - Decrypt file bytes

**File Encryption Flow:**
1. Generate per-file AES-256-GCM key
2. Encrypt file bytes with file key
3. Wrap file key with session key (AES-GCM)
4. Upload encrypted file + wrapped key to server
5. Receiver unwraps file key, decrypts file bytes

**Location:**
- File crypto: `client/src/utils/cryptoUtils.js` (lines 398-489)
- File operations: `client/src/context/KeyExchangeContext.jsx` (lines 504-600)
- Backend: `server/src/controllers/fileController.js`

---

### Phase 7: Audit Logging
**Goal:** Track security events for auditing

**Files Created:**
- `server/src/models/AuditLog.js` - Audit log model
- `server/src/controllers/auditController.js` - Audit operations
- `server/src/routes/auditRoutes.js` - Audit routes

**Files Modified:**
- `client/src/services/apiService.js` - Audit API calls
- `client/src/context/AuthContext.jsx` - Log auth events
- `client/src/context/KeyExchangeContext.jsx` - Log key exchange events
- `client/src/pages/Dashboard.jsx` - Audit log viewer UI
- `client/src/pages/MitmDemo.jsx` - Log MITM detection

**Logged Events:**
- `LOGIN_SUCCESS`, `LOGOUT`
- `IDENTITY_KEY_GENERATED`, `IDENTITY_KEY_LOADED`
- `KEY_EXCHANGE_REQUEST_SENT`, `KEY_EXCHANGE_REQUEST_RECEIVED`
- `KEY_EXCHANGE_RESPONSE_SENT`, `KEY_EXCHANGE_RESPONSE_RECEIVED`
- `KEY_CONFIRM_A_SENT`, `KEY_CONFIRM_A_RECEIVED`
- `KEY_CONFIRM_B_SENT`, `KEY_CONFIRM_B_RECEIVED`
- `SESSION_ESTABLISHED`
- `REPLAY_ATTACK_BLOCKED`
- `MITM_ATTACK_DETECTED`
- `ENCRYPTED_FILE_UPLOAD`, `FILE_DECRYPTED`

**Location:**
- Backend: `server/src/controllers/auditController.js`
- Logging calls: Throughout `AuthContext.jsx` and `KeyExchangeContext.jsx`
- UI: `client/src/pages/Dashboard.jsx` (Security Event Logs section)

---

### Phase 8: Security Hardening & Polishing
**Goal:** Improve security, UX, and error handling

**Files Modified:**
- `client/src/context/KeyExchangeContext.jsx` - Memory cleanup, session validation
- `client/src/context/AuthContext.jsx` - Private key cleanup
- `client/src/pages/Dashboard.jsx` - UI improvements, session reset
- `client/src/pages/MitmDemo.jsx` - Navigation guards
- `client/src/styles.css` - UI/UX improvements
- `server/src/controllers/keyExchangeController.js` - Better error handling

**Key Features:**
- **Memory Cleanup**: Zero sensitive data after use
- **Session Validation**: Prevent actions without valid session
- **Multiple Key Exchange Prevention**: Frontend + backend protection
- **UI/UX Improvements**: Hover animations, spacing, separators
- **Better Error Handling**: User-friendly error messages
- **Navigation Guards**: Protect routes requiring authentication
- **Session Reset**: Clear session state button

**Location:**
- Cleanup functions: `client/src/context/KeyExchangeContext.jsx` (lines 550-570)
- Session reset: `client/src/pages/Dashboard.jsx` (handleResetSession)
- UI improvements: `client/src/styles.css`

---

## Security Features

### Cryptographic Security

1. **Identity Keys**
   - RSA-PSS 2048-bit or ECC P-256
   - Private keys encrypted with AES-256-GCM
   - Key derivation: PBKDF2 (SHA-256, 150,000 iterations)
   - Storage: IndexedDB (client-side only)

2. **Key Exchange**
   - ECDH P-256 for ephemeral keys
   - Digital signatures (RSA-PSS or ECDSA)
   - HKDF (SHA-256) for session key derivation
   - Key confirmation messages

3. **Message Encryption**
   - AES-256-GCM for messages
   - Additional Authenticated Data (AAD) for integrity
   - Replay protection: nonces, timestamps, sequence numbers

4. **File Encryption**
   - Per-file AES-256-GCM keys
   - Key wrapping with session key
   - Client-side encryption/decryption only

### Operational Security

1. **Replay Protection**
   - Nonce uniqueness checks
   - Timestamp validation (30-second window)
   - Sequence number tracking
   - Both client and server validation

2. **Memory Security**
   - Sensitive data zeroed after use
   - Private keys cleared on logout
   - Session keys cleared on reset

3. **Access Control**
   - Navigation guards for protected routes
   - Session validation before operations
   - Identity key verification

4. **Audit Trail**
   - Comprehensive security event logging
   - No sensitive data in logs
   - User-accessible audit logs

---

## File Locations & Responsibilities

### Frontend Core Files

| File | Purpose | Key Functions |
|------|---------|---------------|
| `client/src/App.jsx` | Main app component | Route definitions |
| `client/src/main.jsx` | React entry point | Provider setup |
| `client/src/context/AuthContext.jsx` | Authentication state | `handleRegister()`, `handleLogin()`, `logout()` |
| `client/src/context/KeyExchangeContext.jsx` | Key exchange & messaging | `initiateKeyExchange()`, `sendEncryptedMessage()`, `sendEncryptedFile()` |
| `client/src/services/apiService.js` | API communication | All HTTP requests to backend |
| `client/src/utils/cryptoUtils.js` | Cryptographic operations | All Web Crypto API wrappers |
| `client/src/utils/indexedDBUtils.js` | Local storage | `storePrivateKey()`, `retrievePrivateKey()` |
| `client/src/pages/Dashboard.jsx` | Main UI | Key exchange, messaging, file sharing, audit logs |
| `client/src/pages/MitmDemo.jsx` | MITM demonstration | Attack simulation UI |

### Backend Core Files

| File | Purpose | Key Functions |
|------|---------|---------------|
| `server/src/server.js` | Express app | Server setup, route mounting |
| `server/src/config/db.js` | Database connection | `connectDB()` |
| `server/src/controllers/authController.js` | Authentication | `register()`, `login()`, `getAllUsers()` |
| `server/src/controllers/keyExchangeController.js` | Key exchange | `createRequest()`, `createResponse()`, `createConfirm()` |
| `server/src/controllers/messageController.js` | Messages | `sendMessage()` (with replay checks), `getMessages()` |
| `server/src/controllers/fileController.js` | Files | `uploadEncryptedFile()`, `downloadEncryptedFile()`, `listFiles()` |
| `server/src/controllers/auditController.js` | Audit logs | `logEvent()`, `getUserLogs()` |
| `server/src/models/User.js` | User schema | Username, password hash, public key |
| `server/src/models/Message.js` | Message schema | Encrypted message with metadata |
| `server/src/models/Conversation.js` | Conversation state | Replay protection tracking |

---

## Protocol Flow

### Registration Flow

```
User → Register Form
  ↓
Frontend: Generate RSA-PSS identity key pair
  ↓
Frontend: Encrypt private key with password (PBKDF2 + AES-GCM)
  ↓
Frontend: Store encrypted private key in IndexedDB
  ↓
Frontend: Send username, password hash, public key to backend
  ↓
Backend: Store user in MongoDB
  ↓
Frontend: Log IDENTITY_KEY_GENERATED
  ↓
Redirect to Dashboard
```

**Files Involved:**
- `client/src/pages/Register.jsx`
- `client/src/context/AuthContext.jsx` (lines 24-68)
- `client/src/utils/cryptoUtils.js` (lines 22-154)
- `server/src/controllers/authController.js` (register function)

### Key Exchange Flow

```
Initiator (A)                    Responder (B)
     │                                │
     ├─ Generate ECDH key pair        │
     ├─ Sign ECDH public key          │
     ├─ POST /keyexchange/request ────┼─→ Verify signature
     │                                ├─ Generate ECDH key pair
     │                                ├─ Sign ECDH public key
     │                                ├─ POST /keyexchange/response
     │←─── GET /keyexchange/response ─┤
     ├─ Verify signature              │
     ├─ Derive shared secret (ECDH)   │
     ├─ Derive session key (HKDF)     │
     ├─ Send KEY-CONFIRM-A            │
     │                                ├─ Derive shared secret
     │                                ├─ Derive session key
     │                                ├─ Receive KEY-CONFIRM-A
     │                                ├─ Send KEY-CONFIRM-B
     │←─── GET /keyexchange/confirm ──┤
     ├─ Receive KEY-CONFIRM-B         │
     ├─ Session Established           │
     └─ Session Established           └─
```

**Files Involved:**
- `client/src/context/KeyExchangeContext.jsx` (lines 47-316)
- `server/src/controllers/keyExchangeController.js`
- `client/src/utils/cryptoUtils.js` (lines 156-300)

### Message Sending Flow

```
Sender                              Receiver
  │                                    │
  ├─ Create message object            │
  │  { sender, sequence, nonce,       │
  │    timestamp, plaintext }         │
  ├─ Encrypt with session key         │
  │  (AES-256-GCM + AAD)              │
  ├─ POST /messages/send              │
  │                                    ├─ Backend: Replay checks
  │                                    │  (nonce, sequence, timestamp)
  │                                    ├─ Store in MongoDB
  │                                    │
  │                                    ├─ GET /messages
  │←─── Return encrypted message ─────┤
  │                                    ├─ Decrypt with session key
  │                                    ├─ Replay checks (client-side)
  │                                    └─ Display message
```

**Files Involved:**
- `client/src/context/KeyExchangeContext.jsx` (lines 318-386)
- `server/src/controllers/messageController.js`
- `client/src/utils/cryptoUtils.js` (lines 321-379)

### File Sharing Flow

```
Sender                              Receiver
  │                                    │
  ├─ Read file as ArrayBuffer         │
  ├─ Generate file key (AES-256-GCM)  │
  ├─ Encrypt file with file key       │
  ├─ Wrap file key with session key   │
  ├─ POST /files/upload               │
  │                                    ├─ Store encrypted file
  │                                    │
  │                                    ├─ GET /files
  │←─── Return file list ─────────────┤
  │                                    ├─ GET /files/:id
  │←─── Return encrypted file ────────┤
  │                                    ├─ Unwrap file key
  │                                    ├─ Decrypt file bytes
  │                                    └─ Download Blob
```

**Files Involved:**
- `client/src/context/KeyExchangeContext.jsx` (lines 504-600)
- `server/src/controllers/fileController.js`
- `client/src/utils/cryptoUtils.js` (lines 398-489)

---

## API Endpoints

### Authentication
- `POST /api/v1/auth/register` - Register new user
- `POST /api/v1/auth/login` - Login user
- `GET /api/v1/auth/users` - Get all users
- `GET /api/v1/auth/user/:username` - Get user by username

### Key Exchange
- `POST /api/v1/keyexchange/request` - Create key exchange request
- `GET /api/v1/keyexchange/pending/:username` - Get pending requests
- `POST /api/v1/keyexchange/response` - Create key exchange response
- `GET /api/v1/keyexchange/response/:username` - Get response
- `POST /api/v1/keyexchange/confirm` - Create confirmation
- `GET /api/v1/keyexchange/confirm/:username` - Get confirmation
- `DELETE /api/v1/keyexchange/request` - Delete request

### Messages
- `POST /api/v1/messages/send` - Send encrypted message
- `GET /api/v1/messages?username=...&otherUser=...` - Get messages

### Files
- `POST /api/v1/files/upload` - Upload encrypted file
- `GET /api/v1/files?user=...&peer=...` - List files
- `GET /api/v1/files/:id` - Download encrypted file

### Audit
- `POST /api/v1/audit/log` - Log security event
- `GET /api/v1/audit/:username` - Get audit logs

---

## Cryptographic Operations

### Key Generation

**Identity Keys:**
```javascript
// Location: client/src/utils/cryptoUtils.js (lines 22-47)
generateIdentityKeyPair(algorithm = 'RSA')
  → Returns: { publicKey, privateKey, keyAlgorithm }
```

**ECDH Keys:**
```javascript
// Location: client/src/utils/cryptoUtils.js (lines 156-166)
generateECDHKeyPair()
  → Returns: { publicKey, privateKey }
```

**File Keys:**
```javascript
// Location: client/src/utils/cryptoUtils.js (lines 398-406)
generateFileKey()
  → Returns: AES-256-GCM CryptoKey
```

### Encryption/Decryption

**Private Key Encryption:**
```javascript
// Location: client/src/utils/cryptoUtils.js (lines 98-118)
encryptPrivateKeyWithAES(privateJwk, aesKey, salt, iterations)
  → Returns: { ciphertext, iv, salt, iterations }
```

**Message Encryption:**
```javascript
// Location: client/src/utils/cryptoUtils.js (lines 321-357)
encryptMessageWithMetadata(key, sender, plaintext, sequence)
  → Returns: { ciphertext, iv, nonce, sequence, timestamp }
```

**File Encryption:**
```javascript
// Location: client/src/utils/cryptoUtils.js (lines 408-425)
encryptFileWithKey(fileArrayBuffer, fileKey)
  → Returns: { ciphertext, iv }
```

### Key Exchange

**Signing:**
```javascript
// Location: client/src/utils/cryptoUtils.js (lines 185-221)
signData(privateIdentityKey, data, keyAlgorithm)
  → Returns: Base64 signature
```

**Verification:**
```javascript
// Location: client/src/utils/cryptoUtils.js (lines 223-249)
verifySignature(publicIdentityKey, signature, data)
  → Returns: boolean
```

**Shared Secret Derivation:**
```javascript
// Location: client/src/utils/cryptoUtils.js (lines 251-261)
deriveSharedSecret(ownECDHPrivateKey, peerECDHPublicKey)
  → Returns: ArrayBuffer (256 bits)
```

**Session Key Derivation:**
```javascript
// Location: client/src/utils/cryptoUtils.js (lines 263-287)
hkdfExtractAndExpand(sharedSecret, salt, info, length)
  → Returns: ArrayBuffer (256 bits)
```

---

## Development Guide

### Prerequisites

- Node.js 16+ and npm
- MongoDB (local or Atlas)
- Modern browser with Web Crypto API support

### Setup

1. **Clone Repository**
   ```bash
   cd secure-e2ee-chat
   ```

2. **Backend Setup**
   ```bash
   cd server
   npm install
   # Create .env file with MONGO_URI
   npm start
   ```

3. **Frontend Setup**
   ```bash
   cd client
   npm install
   npm run dev
   ```

### Environment Variables

**Backend (.env):**
```
MONGO_URI=mongodb+srv://user:pass@cluster.mongodb.net/dbname
PORT=5000
```

### Testing the System

1. **Register Two Users**
   - Register `shoukat_` and `hashim_`
   - Identity keys generated automatically

2. **Key Exchange**
   - `shoukat_` initiates key exchange with `hashim_`
   - `hashim_` responds
   - Both poll for confirmations
   - Session established

3. **Send Messages**
   - Type message in chat box
   - Message encrypted and sent
   - Receiver sees decrypted message

4. **Share Files**
   - Select file to send
   - File encrypted and uploaded
   - Receiver downloads and decrypts

5. **View Audit Logs**
   - Click "Load Audit Logs" in Dashboard
   - View all security events

### Common Issues

1. **"Key exchange already in progress"**
   - Wait for current exchange to complete
   - Or reset session

2. **"Session not ready"**
   - Complete key exchange confirmation steps
   - Ensure both users have exchanged KEY-CONFIRM messages

3. **"Replay attack detected"**
   - Normal when refreshing messages
   - System automatically blocks duplicates

### Code Style

- **Frontend**: React functional components with hooks
- **Backend**: Express.js with async/await
- **Crypto**: Web Crypto API only (no external libraries)
- **Error Handling**: Try-catch with user-friendly messages

---

## Security Considerations

### What the Server Never Sees

- Private identity keys
- Session keys
- Plaintext messages
- Decrypted file contents
- ECDH private keys
- Shared secrets

### What the Server Stores

- Username and password hash
- Public identity keys
- Encrypted messages (ciphertext + metadata)
- Encrypted files (ciphertext + wrapped keys)
- Key exchange requests/responses (signed public keys)
- Audit logs (metadata only)

### Threat Model

**Protected Against:**
- Eavesdropping (end-to-end encryption)
- Replay attacks (nonces, timestamps, sequences)
- MITM attacks (digital signatures)
- Server compromise (zero-knowledge architecture)

**Not Protected Against:**
- Client-side malware
- Physical device compromise
- Social engineering
- Weak passwords

---

## Future Enhancements

Potential improvements for future development:

1. **Group Chat**: Extend key exchange to multiple participants
2. **Message Deletion**: Add secure message deletion
3. **Forward Secrecy**: Implement key rotation
4. **Offline Support**: Queue messages when offline
5. **File Chunking**: Support large file uploads
6. **Voice/Video**: Add encrypted media calls
7. **Mobile App**: React Native implementation

---

## Conclusion

This secure end-to-end encrypted chat application demonstrates industry-standard cryptographic protocols implemented entirely in the browser using the Web Crypto API. The system ensures that sensitive data never leaves the client in plaintext form, providing strong security guarantees even if the server is compromised.

All cryptographic operations are performed client-side, with the server acting only as a secure mailbox for encrypted data. The implementation includes comprehensive replay protection, audit logging, and security hardening measures.

---

**Document Version:** 1.0  
**Last Updated:** 2024  
**Maintained By:** Development Team

