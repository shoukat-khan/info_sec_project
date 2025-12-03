#!/usr/bin/env node

const crypto = require('crypto');
const {
  VulnerableDHMITM,
  ProtectedWithSignatures,
  LiveMessageInterception
} = require('./utils/mitmAttackSimulator');

console.log('===========================================================');
console.log('    MITM Attack Demonstration - Educational Purpose         ');
console.log('===========================================================\n');

console.log('-----------------------------------------------------------');
console.log('PART 1: VULNERABLE SCENARIO - DH without Digital Signatures');
console.log('-----------------------------------------------------------\n');

const vulnerableAttack = new VulnerableDHMITM();

console.log('[SCENARIO] Alice and Bob want to establish encrypted channel');
console.log('[SCENARIO] Attacker (Eve) is on the network and intercepts traffic\n');

const aliceKeys = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
const bobKeys = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });

console.log('STEP 1: Key Exchange (WITHOUT Signatures)\n');
console.log('Alice sends public key to Bob');
const aliceIntercepted = vulnerableAttack.interceptPublicKey(
  'Alice',
  aliceKeys.publicKey
);
console.log('→ Attacker replaces Alice\'s key with attacker\'s key\n');

console.log('Bob sends public key to Alice');
const bobIntercepted = vulnerableAttack.interceptPublicKey(
  'Bob',
  bobKeys.publicKey
);
console.log('→ Attacker replaces Bob\'s key with attacker\'s key\n');

console.log('STEP 2: Consequences of No Signature Verification\n');

const summary = vulnerableAttack.getAttackSummary();
console.log(`Attack Type: ${summary.type}`);
console.log(`Vulnerability: ${summary.vulnerability}\n`);

console.log('Attack Sequence:');
summary.attack.forEach((step, i) => {
  console.log(`  ${step}`);
});

console.log('\nImpact:');
Object.entries(summary.impact).forEach(([prop, status]) => {
  console.log(`  ${prop}: ${status}`);
});

console.log('\nCONCLUSION: Without signatures, MITM attack is SUCCESSFUL\n');

console.log('\n-----------------------------------------------------------');
console.log('PART 2: PROTECTED SCENARIO - With Digital Signatures');
console.log('-----------------------------------------------------------\n');

const protectedSystem = new ProtectedWithSignatures();

const aliceRsaKeys = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const bobRsaKeys = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });

console.log('STEP 1: User Registration - Public Keys Stored\n');
console.log('Alice registers: RSA public key stored on server');
console.log('Bob registers: RSA public key stored on server\n');

console.log('STEP 2: Secure Key Exchange with Signatures\n');

const aliceEcdhKeys = crypto.generateKeyPairSync('ec', {
  namedCurve: 'prime256v1'
});
const alicePublicKeyPem = aliceEcdhKeys.publicKey.export({ format: 'pem', type: 'spki' });

const aliceSignature = protectedSystem.signPublicKey(
  'Alice',
  alicePublicKeyPem,
  aliceRsaKeys.privateKey
);

console.log('Alice: ECDH public key signed with RSA private key');
console.log(`Signature: ${aliceSignature.substring(0, 40)}...\n`);

const aliceVerified = protectedSystem.verifyAndAcceptKey(
  'Alice',
  alicePublicKeyPem,
  aliceSignature,
  aliceRsaKeys.publicKey
);

console.log('STEP 3: Attacker Attempts MITM\n');

const attackerRsaKeys = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const attackerEcdhKeys = crypto.generateKeyPairSync('ec', {
  namedCurve: 'prime256v1'
});
const attackerPublicKeyPem = attackerEcdhKeys.publicKey.export({ format: 'pem', type: 'spki' });

const mitmResult = protectedSystem.attemptMITMWithFakeSignature(
  'Alice',
  attackerPublicKeyPem,
  attackerRsaKeys.privateKey,
  aliceRsaKeys.publicKey
);

console.log('\nCONCLUSION: Digital signatures PREVENT MITM attack\n');

const protection = protectedSystem.getProtectionSummary();
console.log('Protection Mechanism:');
protection.mechanism.forEach((step, i) => {
  console.log(`  ${step}`);
});

console.log('\nWhy It Works:');
Object.entries(protection.whyItWorks).forEach(([key, value]) => {
  console.log(`  • ${key}: ${value}`);
});

console.log('\n-----------------------------------------------------------');
console.log('PART 3: Message Tampering Detection (GCM Mode)');
console.log('-----------------------------------------------------------\n');

console.log('STEP 1: Normal Encrypted Message\n');
const plaintext = 'Transfer $1000 to Bob';
const aesKey = crypto.randomBytes(32);
const iv = crypto.randomBytes(12);
const cipher = crypto.createCipheriv('aes-256-gcm', aesKey, iv);

let encrypted = cipher.update(plaintext, 'utf8', 'hex');
encrypted += cipher.final('hex');
const authTag = cipher.getAuthTag();

console.log(`Original message: "${plaintext}"`);
console.log(`Encrypted: ${encrypted.substring(0, 40)}...`);
console.log(`Auth Tag: ${authTag.toString('hex')}\n`);

console.log('STEP 2: Attacker Intercepts and Modifies Message\n');

const tamperedData = LiveMessageInterception.attemptTampering(
  encrypted,
  authTag,
  iv
);

console.log('\nSTEP 3: Recipient Attempts Decryption\n');

const decipher = crypto.createDecipheriv('aes-256-gcm', aesKey, iv);
decipher.setAuthTag(authTag);

try {
  let decrypted = decipher.update(tamperedData.tampered, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  console.log('Decrypted message:', decrypted);
} catch (error) {
  console.log('TAMPERING DETECTED!');
  console.log(`Error: ${error.message}`);
  console.log('\nReason: GCM authentication tag validation failed');
  console.log(
    'Attacker cannot forge authentication tag without knowing the secret key'
  );
}

console.log('\n===========================================================');
console.log('SUMMARY');
console.log('===========================================================\n');

console.log('WITHOUT PROTECTION:');
console.log('  MITM attack possible');
console.log('  Attacker can read messages');
console.log('  Attacker can modify messages');
console.log('  No authenticity guarantee\n');

console.log('WITH OUR PROTECTIONS:');
console.log('  Digital Signatures verify key authenticity');
console.log('  GCM authentication detects tampering');
console.log('  Replay attack protection (timestamps + nonces)');
console.log('  Complete end-to-end security\n');

console.log('KEY TAKEAWAY:');
console.log(
  '  Encryption alone is not enough. You need authentication (signatures)'
);
console.log(
  '  and integrity checks (GCM) to prevent MITM and tampering attacks.\n'
);
