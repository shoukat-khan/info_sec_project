const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

const bufferToBase64 = (buffer) => {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  bytes.forEach((b) => {
    binary += String.fromCharCode(b);
  });
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

export const generateIdentityKeyPair = async (algorithm = 'RSA') => {
  if (algorithm === 'RSA') {
    const keyPair = await window.crypto.subtle.generateKey(
      {
        name: 'RSA-PSS',
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: 'SHA-256'
      },
      true,
      ['sign', 'verify']
    );
    return { ...keyPair, keyAlgorithm: 'RSA' };
  }

  const keyPair = await window.crypto.subtle.generateKey(
    {
      name: 'ECDSA',
      namedCurve: 'P-256'
    },
    true,
    ['sign', 'verify']
  );

  return { ...keyPair, keyAlgorithm: 'ECC' };
};

export const exportPublicKeyJWK = async (publicKey) => {
  return window.crypto.subtle.exportKey('jwk', publicKey);
};

export const exportPrivateKeyJWK = async (privateKey) => {
  return window.crypto.subtle.exportKey('jwk', privateKey);
};

export const deriveKeyFromPassword = async (password, existingSaltBase64) => {
  const iterations = 150000;
  let salt;

  if (existingSaltBase64) {
    salt = new Uint8Array(base64ToBuffer(existingSaltBase64));
  } else {
    salt = window.crypto.getRandomValues(new Uint8Array(16));
  }

  const baseKey = await window.crypto.subtle.importKey(
    'raw',
    textEncoder.encode(password),
    'PBKDF2',
    false,
    ['deriveKey']
  );

  const aesKey = await window.crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt,
      iterations,
      hash: 'SHA-256'
    },
    baseKey,
    {
      name: 'AES-GCM',
      length: 256
    },
    false,
    ['encrypt', 'decrypt']
  );

  return {
    key: aesKey,
    salt: bufferToBase64(salt.buffer),
    iterations
  };
};

export const encryptPrivateKeyWithAES = async (privateJwk, aesKey, salt, iterations) => {
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const json = JSON.stringify(privateJwk);
  const data = textEncoder.encode(json);

  const ciphertextBuffer = await window.crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv
    },
    aesKey,
    data
  );

  return {
    ciphertext: bufferToBase64(ciphertextBuffer),
    iv: bufferToBase64(iv.buffer),
    salt,
    iterations
  };
};

export const decryptPrivateKeyWithAES = async (encryptedObject, aesKey) => {
  const { ciphertext, iv } = encryptedObject;
  const ivBuffer = base64ToBuffer(iv);
  const ciphertextBuffer = base64ToBuffer(ciphertext);

  const decrypted = await window.crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: new Uint8Array(ivBuffer)
    },
    aesKey,
    ciphertextBuffer
  );

  const json = textDecoder.decode(decrypted);
  const jwk = JSON.parse(json);

  const privateKey = await window.crypto.subtle.importKey(
    'jwk',
    jwk,
    jwk.kty === 'RSA'
      ? {
          name: 'RSA-PSS',
          hash: 'SHA-256'
        }
      : {
          name: 'ECDSA',
          namedCurve: 'P-256'
        },
    false,
    jwk.kty === 'RSA' ? ['sign'] : ['sign']
  );

  return privateKey;
};

export const generateECDHKeyPair = async () => {
  const keyPair = await window.crypto.subtle.generateKey(
    {
      name: 'ECDH',
      namedCurve: 'P-256'
    },
    true,
    ['deriveKey', 'deriveBits']
  );
  return keyPair;
};

export const exportECDHPublicKeyJWK = async (publicKey) => {
  return window.crypto.subtle.exportKey('jwk', publicKey);
};

export const importECDHPublicKeyJWK = async (jwk) => {
  return window.crypto.subtle.importKey(
    'jwk',
    jwk,
    {
      name: 'ECDH',
      namedCurve: 'P-256'
    },
    true,
    []
  );
};

export const signData = async (privateIdentityKey, data, keyAlgorithm = null) => {
  const dataBuffer = typeof data === 'string' ? textEncoder.encode(data) : data;
  
  let isRSA = false;
  if (keyAlgorithm) {
    isRSA = keyAlgorithm === 'RSA';
  } else {
    try {
      const keyInfo = await window.crypto.subtle.exportKey('jwk', privateIdentityKey);
      isRSA = keyInfo.kty === 'RSA';
    } catch (error) {
      throw new Error('Cannot determine key type. Please provide keyAlgorithm parameter.');
    }
  }
  
  if (isRSA) {
    const signature = await window.crypto.subtle.sign(
      {
        name: 'RSA-PSS',
        saltLength: 32
      },
      privateIdentityKey,
      dataBuffer
    );
    return bufferToBase64(signature);
  }
  
  const signature = await window.crypto.subtle.sign(
    {
      name: 'ECDSA',
      hash: 'SHA-256'
    },
    privateIdentityKey,
    dataBuffer
  );
  return bufferToBase64(signature);
};

export const verifySignature = async (publicIdentityKey, signature, data) => {
  const dataBuffer = typeof data === 'string' ? textEncoder.encode(data) : data;
  const signatureBuffer = base64ToBuffer(signature);
  const keyInfo = await window.crypto.subtle.exportKey('jwk', publicIdentityKey);
  
  if (keyInfo.kty === 'RSA') {
    return window.crypto.subtle.verify(
      {
        name: 'RSA-PSS',
        saltLength: 32
      },
      publicIdentityKey,
      signatureBuffer,
      dataBuffer
    );
  }
  
  return window.crypto.subtle.verify(
    {
      name: 'ECDSA',
      hash: 'SHA-256'
    },
    publicIdentityKey,
    signatureBuffer,
    dataBuffer
  );
};

export const deriveSharedSecret = async (ownECDHPrivateKey, peerECDHPublicKey) => {
  const sharedSecret = await window.crypto.subtle.deriveBits(
    {
      name: 'ECDH',
      public: peerECDHPublicKey
    },
    ownECDHPrivateKey,
    256
  );
  return sharedSecret;
};

export const hkdfExtractAndExpand = async (sharedSecret, salt, info, length = 256) => {
  const saltBuffer = salt ? (typeof salt === 'string' ? base64ToBuffer(salt) : salt) : new ArrayBuffer(32);
  const infoBuffer = typeof info === 'string' ? textEncoder.encode(info) : info;
  
  const baseKey = await window.crypto.subtle.importKey(
    'raw',
    sharedSecret,
    'HKDF',
    false,
    ['deriveBits']
  );
  
  const derivedBits = await window.crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: saltBuffer,
      info: infoBuffer
    },
    baseKey,
    length
  );
  
  return derivedBits;
};

export const importSessionKey = async (rawBits) => {
  return window.crypto.subtle.importKey(
    'raw',
    rawBits,
    {
      name: 'AES-GCM',
      length: 256
    },
    false,
    ['encrypt', 'decrypt']
  );
};

export const encryptWithSessionKey = async (key, plaintext) => {
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const data = typeof plaintext === 'string' ? textEncoder.encode(plaintext) : plaintext;
  
  const ciphertext = await window.crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv
    },
    key,
    data
  );
  
  return {
    ciphertext: bufferToBase64(ciphertext),
    iv: bufferToBase64(iv.buffer)
  };
};

export const encryptMessageWithMetadata = async (key, sender, plaintext, sequence) => {
  const nonceBytes = window.crypto.getRandomValues(new Uint8Array(16));
  const nonce = bufferToBase64(nonceBytes.buffer);
  const timestamp = Date.now();

  const messageData = {
    sender,
    sequence,
    nonce,
    timestamp,
    plaintext
  };

  const messageJson = JSON.stringify(messageData);
  const messageBuffer = textEncoder.encode(messageJson);

  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const aad = textEncoder.encode(`${sender}|${sequence}|${timestamp}`);

  const ciphertext = await window.crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv,
      additionalData: aad
    },
    key,
    messageBuffer
  );

  return {
    ciphertext: bufferToBase64(ciphertext),
    iv: bufferToBase64(iv.buffer),
    nonce,
    sequence,
    timestamp
  };
};

export const decryptMessageWithMetadata = async (key, encryptedBundle) => {
  const { ciphertext, iv, nonce, sequence, timestamp, sender } = encryptedBundle;
  const ivBuffer = base64ToBuffer(iv);
  const ciphertextBuffer = base64ToBuffer(ciphertext);
  const aad = textEncoder.encode(`${sender}|${sequence}|${timestamp}`);

  const decrypted = await window.crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: new Uint8Array(ivBuffer),
      additionalData: aad
    },
    key,
    ciphertextBuffer
  );

  const messageJson = textDecoder.decode(decrypted);
  const messageData = JSON.parse(messageJson);

  return messageData.plaintext;
};

export const decryptWithSessionKey = async (key, ciphertextBundle) => {
  const { ciphertext, iv } = ciphertextBundle;
  const ivBuffer = base64ToBuffer(iv);
  const ciphertextBuffer = base64ToBuffer(ciphertext);
  
  const decrypted = await window.crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: new Uint8Array(ivBuffer)
    },
    key,
    ciphertextBuffer
  );
  
  return textDecoder.decode(decrypted);
};

export const generateFileKey = async () => {
  return window.crypto.subtle.generateKey(
    {
      name: 'AES-GCM',
      length: 256
    },
    true,
    ['encrypt', 'decrypt']
  );
};

export const encryptFileWithKey = async (fileArrayBuffer, fileKey) => {
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  
  const ciphertext = await window.crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv
    },
    fileKey,
    fileArrayBuffer
  );
  
  return {
    ciphertext: bufferToBase64(ciphertext),
    iv: bufferToBase64(iv.buffer)
  };
};

export const wrapFileKeyWithSessionKey = async (fileKey, sessionKey) => {
  const exportedFileKey = await window.crypto.subtle.exportKey('raw', fileKey);
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  
  const wrappedKey = await window.crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv
    },
    sessionKey,
    exportedFileKey
  );
  
  return {
    wrappedKey: bufferToBase64(wrappedKey),
    iv: bufferToBase64(iv.buffer)
  };
};

export const unwrapFileKeyWithSessionKey = async (wrappedKeyBundle, sessionKey) => {
  const { wrappedKey, iv } = wrappedKeyBundle;
  const ivBuffer = base64ToBuffer(iv);
  const wrappedKeyBuffer = base64ToBuffer(wrappedKey);
  
  const decryptedKeyBytes = await window.crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: new Uint8Array(ivBuffer)
    },
    sessionKey,
    wrappedKeyBuffer
  );
  
  return window.crypto.subtle.importKey(
    'raw',
    decryptedKeyBytes,
    {
      name: 'AES-GCM',
      length: 256
    },
    true,
    ['encrypt', 'decrypt']
  );
};

export const decryptFileWithKey = async (ciphertext, iv, fileKey) => {
  const ivBuffer = base64ToBuffer(iv);
  const ciphertextBuffer = base64ToBuffer(ciphertext);
  
  const decrypted = await window.crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: new Uint8Array(ivBuffer)
    },
    fileKey,
    ciphertextBuffer
  );
  
  return decrypted;
};


