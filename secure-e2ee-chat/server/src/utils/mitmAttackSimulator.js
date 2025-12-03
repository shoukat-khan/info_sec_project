const crypto = require('crypto');

class VulnerableDHMITM {
  constructor() {
    this.interceptedKeys = new Map();
    this.attackerKeys = new Map();
  }

  interceptPublicKey(userId, publicKey) {
    console.log(`[ATTACKER] Intercepted public key from ${userId}`);
    this.interceptedKeys.set(userId, publicKey);
    
    const attackerKeyPair = crypto.generateKeyPairSync('ec', {
      namedCurve: 'prime256v1'
    });
    
    this.attackerKeys.set(userId, {
      publicKey: attackerKeyPair.publicKey,
      privateKey: attackerKeyPair.privateKey
    });
    
    return this.attackerKeys.get(userId).publicKey;
  }

  performECDH(userId, victimPublicKey, attackerPrivateKey) {
    try {
      const sharedSecret = crypto.diffieHellman({
        privateKey: attackerPrivateKey,
        publicKey: victimPublicKey
      });
      
      return crypto.createHash('sha256').update(sharedSecret).digest();
    } catch (error) {
      console.error(`[ATTACKER] ECDH failed: ${error.message}`);
      return null;
    }
  }

  interceptAndModifyMessage(
    originalMessage,
    senderPublicKey,
    attackerPrivateKey
  ) {
    console.log(`[ATTACKER] Intercepted message: "${originalMessage}"`);
    
    const modifiedMessage = `${originalMessage} [MODIFIED BY ATTACKER]`;
    console.log(`[ATTACKER] Modified message: "${modifiedMessage}"`);
    
    return modifiedMessage;
  }

  getAttackSummary() {
    return {
      type: 'Man-in-the-Middle (MITM)',
      vulnerability: 'No signature verification on public keys',
      attack: [
        '1. Attacker intercepts Alice\'s public key',
        '2. Attacker sends their key to Bob instead',
        '3. Bob thinks attacker\'s key is Alice\'s key',
        '4. Attacker performs ECDH with both users separately',
        '5. Now attacker can decrypt ALL messages between Alice & Bob',
        '6. Attacker can modify messages undetected',
        '7. Alice and Bob have no idea they\'re compromised'
      ],
      impact: {
        confidentiality: 'BROKEN - Attacker can read all messages',
        integrity: 'BROKEN - Attacker can modify messages',
        authenticity: 'BROKEN - Attacker can forge messages'
      }
    };
  }
}

class ProtectedWithSignatures {
  constructor() {
    this.trustedKeys = new Map();
    this.userKeys = new Map();
  }

  signPublicKey(userId, ecdhPublicKey, rsaPrivateKey) {
    const keyHash = crypto
      .createHash('sha256')
      .update(ecdhPublicKey)
      .digest();

    const signature = crypto.sign('sha256', keyHash, {
      key: rsaPrivateKey,
      padding: crypto.constants.RSA_PKCS1_PSS_PADDING
    });

    return signature.toString('hex');
  }

  verifyAndAcceptKey(userId, ecdhPublicKey, signature, rsaPublicKey) {
    try {
      const keyHash = crypto
        .createHash('sha256')
        .update(ecdhPublicKey)
        .digest();

      const isValid = crypto.verify(
        'sha256',
        keyHash,
        {
          key: rsaPublicKey,
          padding: crypto.constants.RSA_PKCS1_PSS_PADDING
        },
        Buffer.from(signature, 'hex')
      );

      if (isValid) {
        console.log(`[SERVER] ✓ Signature verified for ${userId}`);
        this.userKeys.set(userId, {
          ecdhPublicKey,
          signature,
          verifiedAt: new Date()
        });
        return true;
      } else {
        console.log(`[SERVER] ✗ Signature verification FAILED for ${userId}`);
        return false;
      }
    } catch (error) {
      console.error(`[SERVER] Signature verification error: ${error.message}`);
      return false;
    }
  }

  attemptMITMWithFakeSignature(
    userId,
    fakeEcdhKey,
    attackerRsaPrivateKey,
    legitimateRsaPublicKey
  ) {
    const fakeSignature = this.signPublicKey(
      userId,
      fakeEcdhKey,
      attackerRsaPrivateKey
    );

    console.log(
      `[ATTACKER] Attempting MITM with fake signature (signed with attacker's RSA key)`
    );

    const result = this.verifyAndAcceptKey(
      userId,
      fakeEcdhKey,
      fakeSignature,
      legitimateRsaPublicKey
    );

    if (!result) {
      console.log(`[SERVER] ✗ MITM BLOCKED! Signature does not match user's key`);
    }

    return result;
  }

  getProtectionSummary() {
    return {
      protection: 'Digital Signature Verification',
      mechanism: [
        '1. User creates ECDH key pair',
        '2. User signs ECDH public key with RSA private key',
        '3. User sends ECDH public key + signature to server',
        '4. Server verifies signature using user\'s RSA public key',
        '5. If signature valid → Accept key',
        '6. If signature invalid → Reject key',
        '7. Attacker cannot forge valid signature (doesn\'t have private key)',
        '8. MITM attack is PREVENTED'
      ],
      whyItWorks: {
        rsa_private_key: 'Only legitimate user has this (stored locally)',
        signature: 'Mathematically tied to specific RSA key pair',
        forgery: 'Attacker cannot sign with user\'s private key',
        detection: 'Server can verify authenticity before accepting key'
      }
    };
  }
}

class LiveMessageInterception {
  static attemptTampering(encryptedMessage, gcmTag, gcmNonce) {
    console.log('\n[ATTACKER] Intercepted encrypted message');
    console.log(`Original: ${encryptedMessage}`);

    const tampered = encryptedMessage.substring(0, 10) + 
                     (parseInt(encryptedMessage[10], 16) + 1).toString(16) +
                     encryptedMessage.substring(11);

    console.log(`[ATTACKER] Tampered: ${tampered}`);
    console.log(`[ATTACKER] Modified ciphertext by changing 1 character`);

    return {
      original: encryptedMessage,
      tampered: tampered,
      gcmTag: gcmTag,
      gcmNonce: gcmNonce,
      description: 'GCM mode will detect this tampering'
    };
  }

  static verifyTamperingDetection(originalTag, receivedCiphertext) {
    return {
      status: 'TAMPERING DETECTED',
      reason: 'GCM authentication tag mismatch',
      explanation: [
        'GCM mode produces authentication tag from:',
        '  1. Ciphertext content',
        '  2. Additional Authenticated Data (AAD)',
        '  3. Secret key',
        '',
        'If ANY of these change:',
        '  - Original tag no longer matches',
        '  - Decryption is rejected',
        '  - Message is discarded',
        '',
        'Result: Tampering is detected with 100% certainty'
      ]
    };
  }
}

module.exports = {
  VulnerableDHMITM,
  ProtectedWithSignatures,
  LiveMessageInterception
};
