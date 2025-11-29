const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

const bufferToBase64 = (buffer) => {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  bytes.forEach((b) => (binary += String.fromCharCode(b)));
  return btoa(binary);
};

const base64ToBuffer = (base64) => {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
};

const getAesKeyFromSharedSecret = async (sharedSecret) => {
  const hashedSecret = await window.crypto.subtle.digest('SHA-256', sharedSecret);
  return window.crypto.subtle.importKey(
    'raw',
    hashedSecret,
    {
      name: 'AES-GCM'
    },
    false,
    ['encrypt', 'decrypt']
  );
};

export const generateECDHKeyPairInsecure = async () => {
  const keyPair = await window.crypto.subtle.generateKey(
    {
      name: 'ECDH',
      namedCurve: 'P-256'
    },
    true,
    ['deriveBits']
  );

  return keyPair;
};

export const exportPublicKeyBase64 = async (publicKey) => {
  const raw = await window.crypto.subtle.exportKey('raw', publicKey);
  return bufferToBase64(raw);
};

export const deriveSharedSecretInsecure = async (privateKey, publicKey) => {
  const secret = await window.crypto.subtle.deriveBits(
    {
      name: 'ECDH',
      public: publicKey
    },
    privateKey,
    256
  );
  return secret;
};

export const encryptWithSharedSecret = async (sharedSecret, plaintext) => {
  const aesKey = await getAesKeyFromSharedSecret(sharedSecret);
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const data = textEncoder.encode(plaintext);

  const ciphertext = await window.crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv
    },
    aesKey,
    data
  );

  return {
    ciphertext: bufferToBase64(ciphertext),
    iv: bufferToBase64(iv.buffer)
  };
};

export const decryptWithSharedSecret = async (sharedSecret, bundle) => {
  const aesKey = await getAesKeyFromSharedSecret(sharedSecret);
  const iv = base64ToBuffer(bundle.iv);
  const ciphertext = base64ToBuffer(bundle.ciphertext);

  const plaintextBuffer = await window.crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: new Uint8Array(iv)
    },
    aesKey,
    ciphertext
  );

  return textDecoder.decode(plaintextBuffer);
};

