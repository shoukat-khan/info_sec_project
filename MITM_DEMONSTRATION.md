# MITM Attack Demonstration Guide

## Three Methods to Demonstrate MITM Attacks

---

## **METHOD 1: Run Automated Demonstration Script**

### Quick Start
```bash
cd server/src
node demonstrateMITM.js
```

**Output Shows:**
- ✅ How DH fails without signatures
- ✅ How signatures prevent MITM
- ✅ How GCM detects tampering
- ✅ Real crypto operations

**Best for:** Quick understanding, presentation, validation

---

## **METHOD 2: Burp Suite - Live Interception**

### Setup Burp Suite

#### Step 1: Install & Configure Burp Suite Community
1. Download from: https://portswigger.net/burp
2. Install and launch Burp Suite
3. Go to **Proxy → Options**
4. Set "Proxy Listeners" to: `127.0.0.1:8080`

#### Step 2: Configure Browser Proxy
**For Chrome:**
```
Settings → Advanced → System → Proxy settings
→ Manual proxy configuration
→ HTTP proxy: 127.0.0.1, Port: 8080
→ HTTPS proxy: 127.0.0.1, Port: 8080
```

**For Firefox:**
```
Settings → Network Settings
→ Manual proxy configuration
→ HTTP: 127.0.0.1 Port: 8080
→ SSL: 127.0.0.1 Port: 8080
```

#### Step 3: Install Burp Certificate
1. In Burp, go to **Proxy → CA Certificate**
2. Click **"Export → DER"** and save as `burp.cer`
3. In Firefox: Settings → Certificates → Import `burp.cer`
4. In Chrome: Settings → Manage certificates → Import `burp.cer` under "Authorities"

---

### Demonstration: Message Interception & Tampering

#### Phase 1: Start Application
```bash
# Terminal 1: Start backend
cd server
npm start

# Terminal 2: Start frontend
cd client
npm run dev

# Terminal 3: Start Burp Suite
# (Already running)
```

#### Phase 2: Intercept Encrypted Message

**Step 1: Configure Burp Interception**
- Burp Suite → Proxy → Intercept → **[ON]**
- Make sure "Intercept is on" is highlighted in red

**Step 2: Send Message Through Proxy**
1. Open browser with proxy enabled
2. Go to `http://localhost:5173`
3. Login as **alice**
4. Select **bob** from user list
5. Type message: `"Important: Transfer $1000 to Bob"`
6. **Click Send**

**Step 3: Observe Interception**
- Burp Suite intercepts the request
- Shows the encrypted payload:
  ```json
  {
    "recipientId": "507f1f77bcf86cd799439011",
    "encryptedMessage": "8a7f2c91e4a8f3d2c1b9a7e6...",
    "signature": "3f8a2c91e4a8f3d2c1b9a7...",
    "timestamp": "2025-12-03T10:15:22Z",
    "nonce": "f3a8c2e1"
  }
  ```

**Step 4: Attempt Tampering**
1. In Burp, click on the encrypted message hex value
2. Modify ONE character in the ciphertext
3. Example: Change `8a7f2c91` to `8a7f2c92`
4. Click **Forward**

**Step 5: Observe Detection on Client**
- Bob receives the message
- **Error appears: "❌ Message integrity verification failed"**
- Client code rejected the tampered message
- GCM authentication tag mismatch detected

---

#### Phase 3: Demonstrate Key Substitution MITM

**Purpose:** Show how signatures prevent key substitution

**Step 1: Capture Key Exchange Request**
1. Start fresh login for new user
2. During key exchange, Burp intercepts the request with public key
3. Shows request structure:
   ```json
   {
     "userId": "507f1f77bcf86cd799439012",
     "publicKey": "-----BEGIN PUBLIC KEY-----...",
     "signature": "3f8a2c91e4a8f3d2c1b9a7...",
     "timestamp": "2025-12-03T10:15:22Z"
   }
   ```

**Step 2: Attempt Key Substitution**
1. In Burp, try to replace the `publicKey` field with attacker's key
2. Server will verify the signature
3. **Signature verification fails** because:
   - Signature was created with user's RSA private key
   - Server verifies with user's RSA public key
   - Attacker's key doesn't match
   - Request is **REJECTED**

**Step 3: Show Error Response**
```json
{
  "success": false,
  "error": "Signature verification failed"
}
```

---

### Advanced Burp Techniques

#### Technique 1: Use Burp Repeater
1. Intercept any message
2. Right-click → **Send to Repeater**
3. Modify and re-send multiple times
4. Observe GCM consistently rejects tampered messages

#### Technique 2: Macro Recording
1. **Proxy → Options → Session Handling Rules**
2. Record normal message flow
3. Replay with modifications
4. Show that tampering is ALWAYS detected

#### Technique 3: Compare Requests
1. **Compare two requests side-by-side**
2. Show original signature vs. tampered signature
3. Demonstrate they're identical (attacker can't forge)

---

## **METHOD 3: Manual cURL Testing**

### Setup

```bash
# Start backend and frontend first
cd server && npm start &
cd ../client && npm run dev &
```

### Test 1: Send Legitimate Message

```bash
curl -X POST http://localhost:5000/api/v1/messages/send \
  -H "Content-Type: application/json" \
  -d '{
    "recipientId": "507f1f77bcf86cd799439011",
    "encryptedMessage": "8a7f2c91e4a8f3d2c1b9a7e6f5d4c3b2a1e0f9d8c7b6a5",
    "signature": "3f8a2c91e4a8f3d2c1b9a7e6f5d4c3b2...",
    "timestamp": "2025-12-03T10:15:22Z",
    "nonce": "f3a8c2e1"
  }'
```

**Response:**
```json
{
  "success": true,
  "message": "Message sent successfully"
}
```

### Test 2: Tamper with Ciphertext

```bash
curl -X POST http://localhost:5000/api/v1/messages/send \
  -H "Content-Type: application/json" \
  -d '{
    "recipientId": "507f1f77bcf86cd799439011",
    "encryptedMessage": "8a7f2c91e4a8f3d2c1b9a7e6f5d4c3b2a1e0f9d8c7b6a6",
    "signature": "3f8a2c91e4a8f3d2c1b9a7e6f5d4c3b2...",
    "timestamp": "2025-12-03T10:15:22Z",
    "nonce": "f3a8c2e1"
  }'
```

**Response on Recipient Side:**
```json
{
  "error": "Message integrity verification failed"
}
```

### Test 3: Replay Attack

```bash
# Send same message twice with identical nonce
curl -X POST http://localhost:5000/api/v1/messages/send ... # First request
curl -X POST http://localhost:5000/api/v1/messages/send ... # Identical request

# Second request gets rejected: "Duplicate nonce detected"
```

---

## **Video Demonstration Script**

### For Your Video (12-15 minutes)

#### Scene Setup (0:00-0:30)
**Speaker:** "We'll now demonstrate MITM attacks using three methods..."

#### Scene 1: Automated Script Demo (0:30-3:00)
```bash
node demonstrateMITM.js
```
- Show all three protections working
- Highlight failure points for attacker
- Point out signature verification

#### Scene 2: Burp Suite - Message Tampering (3:00-6:30)
- Start application
- Setup Burp proxy
- Send message from Alice to Bob
- **Intercept in Burp**
- Modify ciphertext
- Show tampering detection
- **Point out:** "Even 1 bit changed breaks GCM"

#### Scene 3: Burp Suite - Key Substitution (6:30-9:00)
- New user registration
- Intercept public key exchange
- Try to replace key with attacker's key
- **Show signature verification failure**
- **Narrate:** "The signature binds the key to the legitimate user"

#### Scene 4: Protection Explanation (9:00-10:30)
- Show protocol diagram
- Explain signature verification
- Show why attacker can't forge
- Mention GCM prevents tampering

#### Scene 5: Summary (10:30-12:00)
- Recap three attack vectors
- Show all three are prevented
- Conclude: "Defense in depth"

---

## **Attack Vectors to Demonstrate**

| Attack | Method | Detection | Time |
|--------|--------|-----------|------|
| **Message Tampering** | Modify 1 byte in ciphertext | GCM auth tag fails | 1:00 |
| **Key Substitution** | Replace public key | Signature verification fails | 1:30 |
| **Replay Attack** | Send same message twice | Nonce deduplication | 0:45 |
| **Signature Forgery** | Sign with different RSA key | Signature mismatch | 1:15 |

---

## **Key Points for Presentation**

### What Attacker CAN See (Without encryption)
- ✅ Who is communicating (metadata)
- ✅ How many messages
- ✅ Approximate message size
- ✅ Timing of communications

### What Attacker CANNOT See (With encryption)
- ❌ Message content
- ❌ File contents
- ❌ Identities (anonymity possible)
- ❌ Any plaintext data

### What Attacker CAN Try (But Fails)
- ❌ Decrypt messages (no key)
- ❌ Modify messages (GCM detects)
- ❌ Impersonate users (signatures prevent)
- ❌ Replay old messages (nonces prevent)
- ❌ Forge signatures (requires private key)

---

## **Troubleshooting**

### Burp Not Intercepting HTTPS
**Solution:** Re-import Burp CA certificate in browser

### Browser Won't Connect Through Proxy
**Solution:** Restart browser after proxy configuration

### Can't See Decrypted Requests
**Solution:** Burp can only show what's not encrypted. Our messages are encrypted client-side, so Burp sees ciphertext (which is the point!)

### Signature Verification Still Succeeds After Modification
**Solution:** You must modify the ciphertext, not the signature or metadata

---

## **Next Steps**

1. **Run the script:** `node demonstrateMITM.js`
2. **Setup Burp Suite** following the guide above
3. **Record video** capturing both demonstrations
4. **Present findings** in team presentation

---

**Educational Purpose:** This demonstrates real security vulnerabilities and defenses. Understanding attacks helps build better security!
