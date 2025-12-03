# Secure End-to-End Encrypted Chat Application

A production-grade, security-focused chat application demonstrating modern cryptographic protocols and zero-knowledge architecture. Built with **RSA-PSS**, **ECDH**, and **AES-256-GCM** encryption implemented directly in the browser using the Web Crypto API.

## 🔐 Key Security Features

### Cryptographic Foundation
- **RSA-PSS (2048-bit)**: Digital signatures for identity authentication and non-repudiation
- **ECDH P-256**: Ephemeral key agreement for perfect forward secrecy
- **AES-256-GCM**: Authenticated encryption ensuring both confidentiality and integrity
- **Zero-Knowledge Architecture**: Server stores only ciphertext, never has access to plaintext or decryption keys

### Attack Prevention
- **MITM Protection**: Digital signatures + public key verification prevent man-in-the-middle attacks
- **Replay Attack Prevention**: Three-layer defense using timestamps, nonces, and sequence numbers
- **Tampering Detection**: GCM authentication tags immediately detect message modifications
- **Integrity Verification**: All messages authenticated to ensure sender identity

### Security Properties
| Property | Implementation |
|----------|-----------------|
| **Confidentiality** | AES-256-GCM Encryption |
| **Integrity** | GCM Authentication Tags |
| **Authenticity** | RSA-PSS Digital Signatures |
| **Non-Repudiation** | Cryptographic Proof of Origin |

---

## 🎯 Features

### Core Functionality
✅ **End-to-End Encrypted Messaging** - Send secure messages to any user  
✅ **Encrypted File Transfer** - Upload/download files with encryption  
✅ **Real-time Communication** - Live chat with instant message delivery  
✅ **User Authentication** - Secure login with password hashing (bcrypt)  
✅ **Key Management** - Automatic key exchange and session management  
✅ **Audit Logging** - Track all security-relevant events  
✅ **MITM & Replay Attack Demonstrations** - Educational attack/defense examples  

### Security Features
- 🔒 Client-side cryptography (Web Crypto API)
- 🔑 Automatic key exchange protocol
- 📊 Message authentication & integrity verification
- ⏰ Replay attack prevention with timestamps & nonces
- 🛡️ Rate limiting & input validation
- 📝 Comprehensive audit trails

---

## 📋 Project Structure

```
secure-e2ee-chat/
├── README.md
├── docs/
│   ├── project_report.tex          # Detailed technical report
│   ├── TECHNICAL_REPORT.md         # Protocol documentation
│   └── protocol.md                 # Cryptographic protocol specs
│
├── client/                         # React Frontend
│   ├── package.json
│   ├── vite.config.js
│   ├── index.html
│   ├── src/
│   │   ├── main.jsx
│   │   ├── App.jsx
│   │   ├── styles.css
│   │   ├── components/
│   │   │   └── Navbar.jsx          # Navigation component
│   │   ├── context/
│   │   │   ├── AuthContext.jsx     # Authentication state
│   │   │   └── KeyExchangeContext.jsx  # Key exchange state
│   │   ├── pages/
│   │   │   ├── Login.jsx           # Login page
│   │   │   ├── Register.jsx        # Registration page
│   │   │   ├── Dashboard.jsx       # Main chat dashboard
│   │   │   └── MitmDemo.jsx        # MITM attack demonstration
│   │   ├── services/
│   │   │   └── apiService.js       # API communication
│   │   └── utils/
│   │       ├── cryptoUtils.js      # Cryptographic operations
│   │       ├── indexedDBUtils.js   # Local storage management
│   │       └── mitmDemoUtils.js    # MITM demo utilities
│   └── .env.example                # Environment variables template
│
├── server/                         # Node.js/Express Backend
│   ├── package.json
│   ├── .env.example
│   └── src/
│       ├── server.js               # Main server file
│       ├── config/
│       │   └── db.js               # MongoDB configuration
│       ├── controllers/
│       │   ├── authController.js   # Auth logic (register/login)
│       │   ├── messageController.js # Message handling
│       │   ├── keyExchangeController.js # Key exchange
│       │   ├── fileController.js   # File transfer
│       │   └── auditController.js  # Audit logging
│       ├── middleware/
│       │   └── errorHandler.js     # Error handling middleware
│       ├── models/
│       │   ├── User.js             # User model
│       │   ├── Message.js          # Message model
│       │   ├── FileMessage.js      # File message model
│       │   ├── KeyExchangeRequest.js   # Key exchange request
│       │   ├── KeyExchangeResponse.js  # Key exchange response
│       │   ├── KeyExchangeConfirm.js   # Key exchange confirmation
│       │   ├── Conversation.js     # Conversation model
│       │   └── AuditLog.js         # Audit log model
│       ├── routes/
│       │   ├── authRoutes.js       # Auth endpoints
│       │   ├── messageRoutes.js    # Message endpoints
│       │   ├── keyExchangeRoutes.js # Key exchange endpoints
│       │   ├── fileRoutes.js       # File endpoints
│       │   └── auditRoutes.js      # Audit endpoints
│       └── utils/
│           └── validateInput.js    # Input validation
```

---

## 🚀 Getting Started

### Prerequisites
- **Node.js** v16+ and npm
- **MongoDB** (local or Atlas)
- **Modern browser** with Web Crypto API support (Chrome, Firefox, Safari, Edge)
- **Git** for version control

### Installation

#### 1. Clone the Repository
```bash
git clone https://github.com/shoukat-khan/info_sec_project.git
cd secure-e2ee-chat
```

#### 2. Setup Backend Server

```bash
cd server

# Install dependencies
npm install

# Create .env file
cat > .env << EOF
MONGODB_URI=mongodb://localhost:27017/secure-chat
# OR for MongoDB Atlas:
# MONGODB_URI=mongodb+srv://username:password@cluster.mongodb.net/secure-chat

PORT=5000
NODE_ENV=development
EOF

# Start the server
npm start
# Server runs on http://localhost:5000
```

#### 3. Setup Frontend Client

```bash
cd ../client

# Install dependencies
npm install

# Create .env file
cat > .env << EOF
VITE_API_BASE_URL=http://localhost:5000/api/v1
EOF

# Start development server
npm run dev
# Application runs on http://localhost:5173
```

---

## 🔧 Configuration

### Backend Environment Variables (.env)

```env
# Database
MONGODB_URI=mongodb://localhost:27017/secure-chat

# Server
PORT=5000
NODE_ENV=development  # or production

# Optional: For production
# CORS_ORIGIN=https://yourdomain.com
```

### Frontend Environment Variables (.env)

```env
VITE_API_BASE_URL=http://localhost:5000/api/v1
VITE_APP_NAME=SecureChat
```

---

## 📡 API Endpoints

### Authentication
```
POST   /api/v1/auth/register    - Register new user
POST   /api/v1/auth/login       - Login user
GET    /api/v1/auth/user/:username    - Get user by username
GET    /api/v1/auth/users       - Get all users list
```

### Messages
```
POST   /api/v1/messages/send    - Send encrypted message
GET    /api/v1/messages/:userId - Get user's messages
DELETE /api/v1/messages/:messageId - Delete message
```

### Key Exchange
```
POST   /api/v1/keyexchange/initiate  - Initiate key exchange
POST   /api/v1/keyexchange/respond   - Respond to key exchange
POST   /api/v1/keyexchange/confirm   - Confirm key exchange
```

### File Transfer
```
POST   /api/v1/files/upload    - Upload encrypted file
GET    /api/v1/files/:fileId   - Download encrypted file
DELETE /api/v1/files/:fileId   - Delete file
```

### Audit Logs
```
GET    /api/v1/audit/logs      - Get audit logs (admin only)
```

---

## 🔐 Cryptographic Protocol

### Message Encryption Flow

```
1. KEY EXCHANGE
   Alice → Server: Public Key (RSA-PSS)
   ↓
   Alice ↔ Bob: ECDH P-256 Key Agreement
   ↓
   Result: Shared Symmetric Key (AES-256)

2. MESSAGE ENCRYPTION
   Alice's Message → Encryption(AES-256-GCM, Shared Key)
   ↓
   Result: {
     ciphertext: "...",
     nonce: "...",
     authTag: "...",
     timestamp: "...",
     signature: "RSA-PSS(hash)"
   }

3. TRANSMISSION
   Encrypted Message → Server (stored as ciphertext)
   ↓
   Server → Bob (no decryption)

4. DECRYPTION
   Bob receives ciphertext
   ↓
   Verify: RSA-PSS signature ✓
   Decrypt: AES-256-GCM with shared key
   ↓
   Bob reads plaintext message
```

### Replay Attack Prevention

```
Layer 1: TIMESTAMP VALIDATION
  ├─ Message timestamp must be within 5 minutes of server time
  └─ Reject if too old or from future

Layer 2: NONCE DEDUPLICATION
  ├─ Track all used nonces in cache
  └─ Reject if nonce was already processed

Layer 3: SEQUENCE NUMBERS
  ├─ Messages numbered sequentially per conversation
  └─ Reject if out of sequence
```

---

## 🧪 Testing & Demonstrations

### Run Development Servers

```bash
# Terminal 1: Start backend
cd server
npm start

# Terminal 2: Start frontend
cd client
npm run dev
```

### Test Encrypted Messaging
1. Open http://localhost:5173
2. Create two user accounts (e.g., alice, bob)
3. Login as alice, send message to bob
4. Check Network tab in DevTools - message is encrypted ✓
5. Login as bob - message decrypted automatically ✓

### MITM Attack Demonstration
- Navigate to Dashboard → MITM Demo tab
- Follow on-screen instructions to simulate message interception
- Observe how tampering is detected

### File Transfer Test
1. Upload a file from alice to bob
2. Verify file is encrypted in transit (Network tab)
3. Bob downloads and verifies integrity
4. Original file ≈ Downloaded file ✓

---

## 📊 Security Analysis

### STRIDE Threat Model

| Threat | Mitigation | Status |
|--------|-----------|--------|
| **Spoofing** | RSA-PSS digital signatures | ✅ MITIGATED |
| **Tampering** | AES-256-GCM authentication | ✅ MITIGATED |
| **Repudiation** | Digital signature proof | ✅ MITIGATED |
| **Information Disclosure** | End-to-end encryption | ✅ MITIGATED |
| **Denial of Service** | Rate limiting (partial) | ⚠️ PARTIAL |
| **Elevation of Privilege** | Input validation | ✅ MITIGATED |

### Known Limitations

1. **Perfect Forward Secrecy** - Long-term key compromise affects all messages
   - **Future**: Implement session ratcheting (Signal Protocol)

2. **Group Chat** - Only 1-to-1 conversations supported
   - **Future**: Multi-recipient encryption with group key management

3. **DoS Protection** - Limited rate limiting
   - **Future**: Advanced DoS mitigation strategies

4. **Mobile Support** - Web-only, no native apps
   - **Future**: React Native mobile applications

---

## 📚 Documentation

- **[TECHNICAL_REPORT.md](./docs/TECHNICAL_REPORT.md)** - Detailed cryptographic protocol explanation
- **[protocol.md](./docs/protocol.md)** - Protocol specifications and message formats
- **[project_report.tex](./docs/project_report.tex)** - Complete academic report with threat analysis

---

## 🎬 Video Demonstration

A comprehensive video demonstration is available covering:
- ✅ Protocol explanation and cryptographic foundation
- ✅ Live encrypted chat demonstration
- ✅ Secure file upload/download
- ✅ MITM attack interception and detection
- ✅ Replay attack prevention demonstration
- ✅ Security limitations and future improvements

**Duration:** 12-15 minutes | **Quality:** 1080p @ 60fps

---

## 👥 Team Members

This project was developed by a three-member team as part of an Information Security semester course.

**Contributions:**
- **Member 1**: Cryptographic protocol design, backend architecture
- **Member 2**: Security analysis, threat modeling, STRIDE analysis
- **Member 3**: Frontend implementation, UX/UI, integration testing

---

## 📋 Dependencies

### Backend
- **express** - Web framework
- **mongoose** - MongoDB ODM
- **bcrypt** - Password hashing
- **cors** - Cross-origin requests
- **dotenv** - Environment variables

### Frontend
- **react** - UI framework
- **react-router-dom** - Client-side routing
- **vite** - Build tool
- **Web Crypto API** - Native browser cryptography (no external crypto libraries!)

---

## 🛠️ Development

### Adding New Features

1. **Create feature branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Follow code structure** - Place files in appropriate directories

3. **Implement & test** - Ensure security standards are maintained

4. **Submit pull request** - Include description of changes

### Code Standards

- Clear, descriptive variable names
- Comments for complex cryptographic operations
- Input validation on all user inputs
- Error handling with meaningful messages
- Security-first approach (never compromise for convenience)

---

## 🚨 Security Considerations

### For Production Deployment

⚠️ **Before deploying to production:**

1. ✅ Use HTTPS/TLS for all communications
2. ✅ Enable CORS with specific allowed origins
3. ✅ Implement rate limiting (100 requests/min per IP)
4. ✅ Use environment variables for sensitive data (NEVER hardcode)
5. ✅ Enable MongoDB authentication
6. ✅ Setup regular database backups
7. ✅ Implement automated security scanning
8. ✅ Use security headers (CSP, HSTS, etc.)
9. ✅ Enable HTTPS certificate pinning (mobile apps)
10. ✅ Implement proper logging and monitoring

### Security Best Practices

- 🔐 Never store plaintext passwords
- 🔑 Rotate cryptographic keys regularly
- 🛡️ Validate and sanitize all inputs
- 📊 Monitor audit logs for suspicious activity
- 🔄 Keep dependencies updated
- 🧪 Perform regular security audits

---

## 📝 License

This project is an educational demonstration of cryptographic principles and security best practices. Use responsibly.

---

## 🤝 Contributing

Contributions are welcome! Please ensure:
- All tests pass
- Code follows the existing style
- Security is maintained
- Documentation is updated

---

## 📞 Support

For questions or issues:
1. Check the [TECHNICAL_REPORT.md](./docs/TECHNICAL_REPORT.md)
2. Review the API documentation in this README
3. Examine test implementations in the codebase

---

## 🎓 Academic Notes

This project demonstrates:
- ✅ Modern cryptographic implementations
- ✅ Secure architecture design patterns
- ✅ Attack prevention mechanisms
- ✅ Security threat analysis (STRIDE)
- ✅ Practical Web Security
- ✅ Client-side cryptography best practices

**Disclaimer:** This is an educational project. While security principles are correctly implemented, production deployment requires additional hardening and professional security audits.

---

## 📅 Project Timeline

- **Phase 1**: Requirements & cryptographic protocol design
- **Phase 2**: Backend API implementation
- **Phase 3**: Frontend UI & cryptography integration
- **Phase 4**: Testing & attack demonstrations
- **Phase 5**: Documentation & video demonstration

---

**Last Updated:** December 2025  
**Status:** ✅ Complete and Documented
