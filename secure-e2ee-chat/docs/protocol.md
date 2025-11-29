## Secure E2EE Chat – Protocol Overview

This document explains how the secure end-to-end encryption protocol works across the application.

### File Location
This file lives at `docs/protocol.md`.

### 1. Identity Keys (Phase 2)
- When a user registers, the frontend generates an RSA-PSS identity key pair using Web Crypto.
- The public key (JWK) and key algorithm are sent to the backend (`/api/v1/auth/register`) and stored in MongoDB.
- The private key is encrypted locally via AES-256-GCM (key derived from password using PBKDF2) and stored in IndexedDB.
- On login, the encrypted private key is decrypted locally, never leaving the client.

### 2. Key Exchange (Phase 3)
- The initiator generates an ephemeral ECDH P-256 key pair and signs the public key with their identity private key.
- The signed ECDH public key is posted to `/api/v1/keyexchange/request`.
- The responder verifies the signature using the initiator’s public identity key. If valid, the responder generates their ECDH key pair, signs it, and posts it to `/api/v1/keyexchange/response`.
- Both sides derive a shared secret via ECDH, run HKDF(SHA-256) to obtain a 256-bit session key, and exchange KEY-CONFIRM messages (AES-GCM encrypted) to prove key possession.

### 3. Messaging (Phases 4 & 6)
- Every message is wrapped in metadata: `{ sender, sequence, nonce, timestamp, plaintext }`, then encrypted with AES-256-GCM using the session key. Nonces (16 bytes) and timestamps enable replay detection.
- The backend (`/api/v1/messages/send`) stores only ciphertext plus metadata, never plaintext.
- Replay protection checks (timestamp, sequence, nonce) exist on both the backend (Conversation model) and frontend (`receiveEncryptedMessage`).

### 4. File Sharing (Phase 6)
- For each file:
  1. Generate a per-file AES-256-GCM key (fileKey).
  2. Encrypt file bytes with that fileKey.
  3. Wrap fileKey with the session key (AES-GCM).
  4. Upload metadata + encrypted file via `/api/v1/files/upload`.
- To download, the receiver retrieves the encrypted record, unwraps the fileKey with the session key, decrypts the file bytes, and reconstructs the Blob locally.

### 5. MITM Demo (Phase 5)
- `/mitm-demo` demonstrates two flows:
  - **Insecure**: Unsigned ECDH exchange where Mallory swaps public keys and decrypts messages.
  - **Secure**: Signed key exchange where signature verification fails when Mallory attempts the substitution.

### 6. Audit Logging (Phase 7)
- Security events (logins, key exchange steps, replay blocks, file uploads, MITM detection, etc.) are logged client-side using `logSecurityEvent()` and stored via `/api/v1/audit/log`.
- Users can view their logs in the Dashboard (Security Event Logs card) using `/api/v1/audit/:username`.

### 7. Session Cleanup & Guards (Phase 8)
- Session reset and logout wipe session keys, ECDH keys, and sequences via `cleanupSensitiveData()` and `cleanupPrivateKey()`.
- UI components disable actions when the session is not established, and protected routes redirect to `/login` if identity keys are missing.

