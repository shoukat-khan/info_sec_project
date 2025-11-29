import { createContext, useContext, useState } from 'react';
import { useAuth } from './AuthContext';
import {
  generateECDHKeyPair,
  exportECDHPublicKeyJWK,
  importECDHPublicKeyJWK,
  signData,
  verifySignature,
  deriveSharedSecret,
  hkdfExtractAndExpand,
  importSessionKey,
  encryptWithSessionKey,
  decryptWithSessionKey,
  exportPublicKeyJWK,
  encryptMessageWithMetadata,
  decryptMessageWithMetadata
} from '../utils/cryptoUtils';
import {
  createKeyExchangeRequest,
  getPendingKeyExchangeRequests,
  createKeyExchangeResponse,
  getKeyExchangeResponse,
  createKeyExchangeConfirm,
  getKeyExchangeConfirm,
  getUserByUsername,
  sendMessage as sendMessageAPI,
  getMessages as getMessagesAPI,
  deleteKeyExchangeRequest,
  uploadEncryptedFile as uploadEncryptedFileAPI,
  getFileList as getFileListAPI,
  downloadEncryptedFile as downloadEncryptedFileAPI,
  logSecurityEvent
} from '../services/apiService';
import {
  generateFileKey,
  encryptFileWithKey,
  wrapFileKeyWithSessionKey,
  unwrapFileKeyWithSessionKey,
  decryptFileWithKey
} from '../utils/cryptoUtils';

const KeyExchangeContext = createContext(null);

export const KeyExchangeProvider = ({ children }) => {
  const { user, privateKey } = useAuth();
  const [ephemeralECDHPrivateKey, setEphemeralECDHPrivateKey] = useState(null);
  const [ephemeralECDHPublicKey, setEphemeralECDHPublicKey] = useState(null);
  const [sessionKey, setSessionKey] = useState(null);
  const [keyExchangeStatus, setKeyExchangeStatus] = useState('');
  const [pendingRequests, setPendingRequests] = useState([]);
  const [currentExchange, setCurrentExchange] = useState(null);
  const [outgoingSequence, setOutgoingSequence] = useState(1);
  const [incomingSequences, setIncomingSequences] = useState({});
  const [seenNonces, setSeenNonces] = useState({});
  const [sessionPartner, setSessionPartner] = useState(null);
  const [sessionReady, setSessionReady] = useState(false);
  const [fileList, setFileList] = useState([]);
  const [fileStatus, setFileStatus] = useState('');
  const [keyExchangeInProgress, setKeyExchangeInProgress] = useState(false);

  const initiateKeyExchange = async (targetUsername) => {
    try {
      if (!user || !privateKey) {
        throw new Error('User must be logged in with identity key loaded');
      }

      if (keyExchangeInProgress) {
        throw new Error('A key exchange is already in progress');
      }

      setKeyExchangeInProgress(true);
      setKeyExchangeStatus('Generating ECDH key pair...');
      const ecdhKeyPair = await generateECDHKeyPair();
      setEphemeralECDHPrivateKey(ecdhKeyPair.privateKey);
      setEphemeralECDHPublicKey(ecdhKeyPair.publicKey);

      const publicKeyJwk = await exportECDHPublicKeyJWK(ecdhKeyPair.publicKey);
      const publicKeyString = JSON.stringify(publicKeyJwk);

      setKeyExchangeStatus('Signing ECDH public key...');
      const signature = await signData(privateKey, publicKeyString, user.keyAlgorithm);

      setKeyExchangeStatus('Sending key exchange request...');
      await createKeyExchangeRequest({
        requesterUsername: user.username,
        targetUsername,
        ecdhPublicKey: publicKeyString,
        signature
      });

      setCurrentExchange({ targetUsername, role: 'initiator' });
      setSessionPartner(targetUsername);
      setSessionReady(false);
      setKeyExchangeStatus('Initiator request sent');
      
      try {
        await logSecurityEvent({
          username: user.username,
          eventType: 'KEY_EXCHANGE_REQUEST_SENT',
          details: { target: targetUsername }
        });
      } catch (logError) {
        console.error('Failed to log security event:', logError);
      }
    } catch (error) {
      setKeyExchangeInProgress(false);
      setKeyExchangeStatus(`Error: ${error.message}`);
      throw error;
    }
  };

  const loadPendingKeyExchangeRequests = async () => {
    try {
      if (!user) {
        throw new Error('User must be logged in');
      }

      const response = await getPendingKeyExchangeRequests(user.username);
      setPendingRequests(response.data.requests || []);
      return response.data.requests || [];
    } catch (error) {
      setKeyExchangeStatus(`Error loading requests: ${error.message}`);
      throw error;
    }
  };

  const respondToKeyExchange = async (request) => {
    try {
      if (!user || !privateKey) {
        throw new Error('User must be logged in with identity key loaded');
      }

      setKeyExchangeStatus('Verifying sender signature...');
      const targetUserResponse = await getUserByUsername(request.requesterUsername);
      const targetUser = targetUserResponse.data.user;

      if (!targetUser.publicKey) {
        throw new Error('Target user has no public key');
      }

      const targetPublicKeyJwk = JSON.parse(targetUser.publicKey);
      const targetPublicKey = await window.crypto.subtle.importKey(
        'jwk',
        targetPublicKeyJwk,
        targetUser.keyAlgorithm === 'RSA'
          ? {
              name: 'RSA-PSS',
              hash: 'SHA-256'
            }
          : {
              name: 'ECDSA',
              namedCurve: 'P-256'
            },
        true,
        ['verify']
      );

      const isValid = await verifySignature(
        targetPublicKey,
        request.signature,
        request.ecdhPublicKey
      );

      if (!isValid) {
        throw new Error('Invalid signature from requester');
      }

      setKeyExchangeStatus('Signatures verified. Generating ECDH key pair...');
      const ecdhKeyPair = await generateECDHKeyPair();
      setEphemeralECDHPrivateKey(ecdhKeyPair.privateKey);
      setEphemeralECDHPublicKey(ecdhKeyPair.publicKey);

      const publicKeyJwk = await exportECDHPublicKeyJWK(ecdhKeyPair.publicKey);
      const publicKeyString = JSON.stringify(publicKeyJwk);

      setKeyExchangeStatus('Signing response...');
      const signature = await signData(privateKey, publicKeyString, user.keyAlgorithm);

      setKeyExchangeStatus('Sending ECDH response...');
      await createKeyExchangeResponse({
        responderUsername: user.username,
        targetUsername: request.requesterUsername,
        ecdhPublicKey: publicKeyString,
        signature
      });

      setKeyExchangeStatus('Deriving shared secret...');
      const initiatorECDHPublicKeyJwk = JSON.parse(request.ecdhPublicKey);
      const initiatorECDHPublicKey = await importECDHPublicKeyJWK(initiatorECDHPublicKeyJwk);
      const sharedSecret = await deriveSharedSecret(ecdhKeyPair.privateKey, initiatorECDHPublicKey);

      setKeyExchangeStatus('Running HKDF...');
      const salt = new Uint8Array(32);
      const info = new TextEncoder().encode('ECDH-Session-Key');
      const sessionKeyBits = await hkdfExtractAndExpand(sharedSecret, salt, info, 256);

      setKeyExchangeStatus('Importing session key...');
      const importedSessionKey = await importSessionKey(sessionKeyBits);
      setSessionKey(importedSessionKey);

      await deleteKeyExchangeRequest(request.requesterUsername, user.username);

      setCurrentExchange({ targetUsername: request.requesterUsername, role: 'responder' });
      setSessionPartner(request.requesterUsername);
      setSessionReady(false);
      setKeyExchangeStatus('ECDH response sent. Session key derived. Waiting for KEY-CONFIRM-A...');
      setKeyExchangeInProgress(false);
      
      try {
        await logSecurityEvent({
          username: user.username,
          eventType: 'KEY_EXCHANGE_REQUEST_RECEIVED',
          details: { from: request.requesterUsername }
        });
        await logSecurityEvent({
          username: user.username,
          eventType: 'KEY_EXCHANGE_RESPONSE_SENT',
          details: { target: request.requesterUsername }
        });
      } catch (logError) {
        console.error('Failed to log security event:', logError);
      }
    } catch (error) {
      setKeyExchangeInProgress(false);
      setKeyExchangeStatus(`Error: ${error.message}`);
      throw error;
    }
  };

  const pollForResponse = async () => {
    try {
      if (!user || !privateKey || !ephemeralECDHPrivateKey) {
        throw new Error('Must be logged in and have initiated key exchange');
      }

      setKeyExchangeStatus('Polling for response...');
      const response = await getKeyExchangeResponse(user.username);

      if (!response.data.response) {
        setKeyExchangeStatus('No response yet');
        return null;
      }

      const responseData = response.data.response;

      setKeyExchangeStatus('Verifying responder signature...');
      const responderUserResponse = await getUserByUsername(responseData.responderUsername);
      const responderUser = responderUserResponse.data.user;

      if (!responderUser.publicKey) {
        throw new Error('Responder has no public key');
      }

      const responderPublicKeyJwk = JSON.parse(responderUser.publicKey);
      const responderPublicKey = await window.crypto.subtle.importKey(
        'jwk',
        responderPublicKeyJwk,
        responderUser.keyAlgorithm === 'RSA'
          ? {
              name: 'RSA-PSS',
              hash: 'SHA-256'
            }
          : {
              name: 'ECDSA',
              namedCurve: 'P-256'
            },
        true,
        ['verify']
      );

      const isValid = await verifySignature(
        responderPublicKey,
        responseData.signature,
        responseData.ecdhPublicKey
      );

      if (!isValid) {
        throw new Error('Invalid signature from responder');
      }

      setKeyExchangeStatus('Signatures verified. Deriving shared secret...');
      const peerECDHPublicKeyJwk = JSON.parse(responseData.ecdhPublicKey);
      const peerECDHPublicKey = await importECDHPublicKeyJWK(peerECDHPublicKeyJwk);

      const sharedSecret = await deriveSharedSecret(ephemeralECDHPrivateKey, peerECDHPublicKey);

      setKeyExchangeStatus('Running HKDF...');
      const salt = new Uint8Array(32);
      const info = new TextEncoder().encode('ECDH-Session-Key');
      const sessionKeyBits = await hkdfExtractAndExpand(sharedSecret, salt, info, 256);

      setKeyExchangeStatus('Importing session key...');
      const importedSessionKey = await importSessionKey(sessionKeyBits);
      setSessionKey(importedSessionKey);

      setKeyExchangeStatus('Sending KEY-CONFIRM-A...');
      const confirmA = await encryptWithSessionKey(importedSessionKey, 'KEY-CONFIRM-A');
      await createKeyExchangeConfirm({
        senderUsername: user.username,
        targetUsername: responseData.responderUsername,
        confirmMessage: JSON.stringify(confirmA)
      });

      setSessionPartner(responseData.responderUsername);
      setSessionReady(false);
      setKeyExchangeStatus('KEY-CONFIRM-A sent');
      setKeyExchangeInProgress(false);
      
      try {
        await logSecurityEvent({
          username: user.username,
          eventType: 'KEY_EXCHANGE_RESPONSE_RECEIVED',
          details: { from: responseData.responderUsername }
        });
        await logSecurityEvent({
          username: user.username,
          eventType: 'KEY_CONFIRM_A_SENT',
          details: { target: responseData.responderUsername }
        });
      } catch (logError) {
        console.error('Failed to log security event:', logError);
      }
      
      return responseData;
    } catch (error) {
      setKeyExchangeInProgress(false);
      setKeyExchangeStatus(`Error: ${error.message}`);
      throw error;
    }
  };

  const pollForConfirm = async () => {
    try {
      if (!user || !sessionKey) {
        throw new Error('Must have session key established');
      }

      setKeyExchangeStatus('Polling for confirmation...');
      const response = await getKeyExchangeConfirm(user.username);

      if (!response.data.confirm) {
        setKeyExchangeStatus('No confirmation yet');
        return null;
      }

      const confirmData = response.data.confirm;
      const confirmBundle = JSON.parse(confirmData.confirmMessage);

      setKeyExchangeStatus('Decrypting confirmation...');
      const decrypted = await decryptWithSessionKey(sessionKey, confirmBundle);

      if (decrypted === 'KEY-CONFIRM-A') {
        setOutgoingSequence(1);
        setIncomingSequences({});
        setSeenNonces({});
        setSessionPartner(confirmData.senderUsername);
        setSessionReady(true);
        setKeyExchangeStatus('KEY-CONFIRM-A received. Sending KEY-CONFIRM-B...');
        const confirmB = await encryptWithSessionKey(sessionKey, 'KEY-CONFIRM-B');
        await createKeyExchangeConfirm({
          senderUsername: user.username,
          targetUsername: confirmData.senderUsername,
          confirmMessage: JSON.stringify(confirmB)
        });
        setKeyExchangeStatus('KEY-CONFIRM-B sent');
        
        try {
          await logSecurityEvent({
            username: user.username,
            eventType: 'KEY_CONFIRM_A_RECEIVED',
            details: { from: confirmData.senderUsername }
          });
          await logSecurityEvent({
            username: user.username,
            eventType: 'KEY_CONFIRM_B_SENT',
            details: { target: confirmData.senderUsername }
          });
          await logSecurityEvent({
            username: user.username,
            eventType: 'SESSION_ESTABLISHED',
            details: { partner: confirmData.senderUsername }
          });
        } catch (logError) {
          console.error('Failed to log security event:', logError);
        }
      } else if (decrypted === 'KEY-CONFIRM-B') {
        setOutgoingSequence(1);
        setIncomingSequences({});
        setSeenNonces({});
        setSessionReady(true);
        setKeyExchangeStatus('Secure Session Established');
        
        try {
          await logSecurityEvent({
            username: user.username,
            eventType: 'KEY_CONFIRM_B_RECEIVED',
            details: { from: confirmData.senderUsername }
          });
          await logSecurityEvent({
            username: user.username,
            eventType: 'SESSION_ESTABLISHED',
            details: { partner: confirmData.senderUsername }
          });
        } catch (logError) {
          console.error('Failed to log security event:', logError);
        }
      } else {
        throw new Error('Invalid confirmation message');
      }

      return confirmData;
    } catch (error) {
      setKeyExchangeStatus(`Error: ${error.message}`);
      throw error;
    }
  };

  const sendEncryptedMessage = async (receiver, plaintext) => {
    if (!sessionKey || !user) {
      throw new Error('Session key not established or user not logged in');
    }

    if (!sessionReady) {
      throw new Error('Session not ready. Please complete key exchange confirmation.');
    }

    if (!sessionPartner || sessionPartner !== receiver) {
      throw new Error('Invalid session partner. Please establish a session with this user.');
    }

    const currentSequence = outgoingSequence;
    const encrypted = await encryptMessageWithMetadata(
      sessionKey,
      user.username,
      plaintext,
      currentSequence
    );

    await sendMessageAPI({
      sender: user.username,
      receiver,
      ...encrypted
    });

    setOutgoingSequence(currentSequence + 1);
    return encrypted;
  };

  const receiveEncryptedMessage = async (encryptedMessage, options = {}) => {
    const { skipReplayChecks = false } = options;
    if (!sessionKey || !user) {
      throw new Error('Session key not established or user not logged in');
    }

    const { sender, sequence, nonce, timestamp } = encryptedMessage;
    const conversationKey = [user.username, sender].sort().join('|');

    const now = Date.now();
    const timeDiff = Math.abs(now - timestamp);
    const TIMESTAMP_TOLERANCE_MS = 30000;

    if (!skipReplayChecks) {
      if (timeDiff > TIMESTAMP_TOLERANCE_MS) {
        try {
          await logSecurityEvent({
            username: user.username,
            eventType: 'REPLAY_ATTACK_BLOCKED',
            details: { reason: 'timestamp_out_of_tolerance', sender, sequence, timestamp }
          });
        } catch (logError) {
          console.error('Failed to log security event:', logError);
        }
        throw new Error('Replay attack detected: timestamp out of tolerance window');
      }

      const lastSequence = incomingSequences[conversationKey] || 0;
      if (sequence <= lastSequence) {
        try {
          await logSecurityEvent({
            username: user.username,
            eventType: 'REPLAY_ATTACK_BLOCKED',
            details: { reason: 'sequence_not_increasing', sender, sequence, lastSequence }
          });
        } catch (logError) {
          console.error('Failed to log security event:', logError);
        }
        throw new Error('Replay attack detected: sequence number not increasing');
      }

      const nonceKey = `${conversationKey}|${nonce}`;
      if (seenNonces[nonceKey]) {
        try {
          await logSecurityEvent({
            username: user.username,
            eventType: 'REPLAY_ATTACK_BLOCKED',
            details: { reason: 'nonce_already_used', sender, sequence, nonce }
          });
        } catch (logError) {
          console.error('Failed to log security event:', logError);
        }
        throw new Error('Replay attack detected: nonce already used');
      }
    }

    const plaintext = await decryptMessageWithMetadata(sessionKey, encryptedMessage);

    if (!skipReplayChecks) {
      setIncomingSequences((prev) => ({
        ...prev,
        [conversationKey]: sequence
      }));

      const nonceKey = `${conversationKey}|${nonce}`;
      setSeenNonces((prev) => ({
        ...prev,
        [nonceKey]: timestamp
      }));
    }

    return { plaintext, sender, sequence, timestamp, nonce };
  };

  const sendEncryptedFile = async (file, receiver) => {
    if (!sessionKey || !user) {
      throw new Error('Session key not established or user not logged in');
    }

    if (!sessionReady) {
      throw new Error('Session not ready. Please complete key exchange confirmation.');
    }

    if (!receiver || !sessionPartner || sessionPartner !== receiver) {
      throw new Error('Invalid session partner. Please establish a session with this user.');
    }

    let fileArrayBuffer = null;
    let fileKey = null;
    
    try {
      setFileStatus('Reading file...');
      fileArrayBuffer = await file.arrayBuffer();

      setFileStatus('Generating file encryption key...');
      fileKey = await generateFileKey();

      setFileStatus('Encrypting file...');
      const { ciphertext, iv: fileIv } = await encryptFileWithKey(fileArrayBuffer, fileKey);

      setFileStatus('Wrapping file key with session key...');
      const { wrappedKey: wrappedFileKey, iv: keyIv } = await wrapFileKeyWithSessionKey(fileKey, sessionKey);

      setFileStatus('Uploading encrypted file...');
      const uploadData = {
        sender: user.username,
        receiver,
        filename: file.name,
        mimeType: file.type || 'application/octet-stream',
        filesize: file.size,
        ciphertext,
        fileIv,
        wrappedFileKey,
        keyIv
      };

      await uploadEncryptedFileAPI(uploadData);

      setFileStatus('File uploaded successfully');
      
      try {
        await logSecurityEvent({
          username: user.username,
          eventType: 'ENCRYPTED_FILE_UPLOAD',
          details: { receiver, filename: file.name, filesize: file.size, mimeType: file.type || 'application/octet-stream' }
        });
      } catch (logError) {
        console.error('Failed to log security event:', logError);
      }
      
      await loadFileList(receiver);
    } catch (error) {
      setFileStatus(`Error: ${error.message}`);
      throw new Error(error.message || 'File upload failed. Please try again.');
    } finally {
      if (fileArrayBuffer) {
        new Uint8Array(fileArrayBuffer).fill(0);
      }
      fileKey = null;
    }
  };

  const loadFileList = async (peer) => {
    if (!user || !peer) {
      throw new Error('User must be logged in and peer username required');
    }

    try {
      setFileStatus('Loading file list...');
      const response = await getFileListAPI(user.username, peer);
      setFileList(response.data.files || []);
      setFileStatus('');
    } catch (error) {
      setFileStatus(`Error loading files: ${error.message}`);
      throw error;
    }
  };

  const downloadAndDecryptFile = async (fileId) => {
    if (!sessionKey || !user) {
      throw new Error('Session key not established or user not logged in');
    }

    try {
      setFileStatus('Downloading encrypted file...');
      const response = await downloadEncryptedFileAPI(fileId);
      const fileData = response.data.file;

      if (fileData.receiver !== user.username && fileData.sender !== user.username) {
        throw new Error('Unauthorized: You are not the sender or receiver of this file');
      }

      setFileStatus('Unwrapping file key...');
      const fileKey = await unwrapFileKeyWithSessionKey(
        {
          wrappedKey: fileData.wrappedFileKey,
          iv: fileData.keyIv
        },
        sessionKey
      );

      setFileStatus('Decrypting file...');
      const decryptedArrayBuffer = await decryptFileWithKey(
        fileData.ciphertext,
        fileData.fileIv,
        fileKey
      );

      setFileStatus('Preparing download...');
      const blob = new Blob([decryptedArrayBuffer], { type: fileData.mimeType });
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = fileData.filename;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      URL.revokeObjectURL(url);

      setFileStatus('File downloaded successfully');
      
      try {
        await logSecurityEvent({
          username: user.username,
          eventType: 'FILE_DECRYPTED',
          details: { sender: fileData.sender, receiver: fileData.receiver, filename: fileData.filename, filesize: fileData.filesize }
        });
      } catch (logError) {
        console.error('Failed to log security event:', logError);
      }
    } catch (error) {
      setFileStatus(`Error: ${error.message}`);
      throw error;
    }
  };

  const cleanupSensitiveData = () => {
    if (sessionKey) {
      setSessionKey(null);
    }
    if (ephemeralECDHPrivateKey) {
      setEphemeralECDHPrivateKey(null);
    }
    if (ephemeralECDHPublicKey) {
      setEphemeralECDHPublicKey(null);
    }
    setOutgoingSequence(1);
    setIncomingSequences({});
    setSeenNonces({});
  };

  const resetSession = () => {
    cleanupSensitiveData();
    setCurrentExchange(null);
    setSessionPartner(null);
    setSessionReady(false);
    setFileList([]);
    setFileStatus('');
    setKeyExchangeInProgress(false);
  };

  const value = {
    ephemeralECDHPrivateKey,
    ephemeralECDHPublicKey,
    sessionKey,
    keyExchangeStatus,
    pendingRequests,
    currentExchange,
    outgoingSequence,
    incomingSequences,
    sessionPartner,
    sessionReady,
    fileList,
    fileStatus,
    keyExchangeInProgress,
    initiateKeyExchange,
    loadPendingKeyExchangeRequests,
    respondToKeyExchange,
    pollForResponse,
    pollForConfirm,
    sendEncryptedMessage,
    receiveEncryptedMessage,
    sendEncryptedFile,
    loadFileList,
    downloadAndDecryptFile,
    resetSession,
    cleanupSensitiveData,
    setKeyExchangeStatus
  };

  return <KeyExchangeContext.Provider value={value}>{children}</KeyExchangeContext.Provider>;
};

export const useKeyExchange = () => useContext(KeyExchangeContext);

