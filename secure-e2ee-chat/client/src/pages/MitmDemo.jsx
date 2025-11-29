import { useAuth } from '../context/AuthContext';
import { useState, useRef, useEffect } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import {
  generateECDHKeyPairInsecure,
  exportPublicKeyBase64,
  deriveSharedSecretInsecure,
  encryptWithSharedSecret,
  decryptWithSharedSecret
} from '../utils/mitmDemoUtils';
import { signData, verifySignature } from '../utils/cryptoUtils';
import { logSecurityEvent } from '../services/apiService';

const MitmDemo = () => {
  const { user, privateKey } = useAuth();
  const navigate = useNavigate();

  useEffect(() => {
    if (!user) {
      navigate('/login');
    }
  }, [user, navigate]);

  useEffect(() => {
    if (user && !privateKey) {
      navigate('/login', { state: { error: 'Identity key missing. Please log in again.' } });
    }
  }, [user, privateKey, navigate]);
  const insecureRefs = useRef({
    shoukatKeys: null,
    hashimKeys: null,
    malloryKeys: null,
    sharedShoukatMallory: null,
    sharedHashimMallory: null
  });

  const [insecureState, setInsecureState] = useState({
    shoukatPublic: '',
    hashimPublic: '',
    malloryPublic: '',
    sharedShoukatMallory: '',
    sharedHashimMallory: '',
    attackStatus: '',
    malloryInsight: ''
  });

  const [secureState, setSecureState] = useState({
    secureStatus: '',
    mitmStatus: '',
    error: ''
  });

  const handleGenerateInsecure = async () => {
    const shoukatKeys = await generateECDHKeyPairInsecure();
    const hashimKeys = await generateECDHKeyPairInsecure();

    insecureRefs.current = {
      shoukatKeys,
      hashimKeys,
      malloryKeys: null,
      sharedShoukatMallory: null,
      sharedHashimMallory: null
    };

    const shoukatPublic = await exportPublicKeyBase64(shoukatKeys.publicKey);
    const hashimPublic = await exportPublicKeyBase64(hashimKeys.publicKey);

    setInsecureState((prev) => ({
      ...prev,
      shoukatPublic,
      hashimPublic,
      malloryPublic: '',
      sharedShoukatMallory: '',
      sharedHashimMallory: '',
      attackStatus: 'Keys generated without signatures. Ready for interception.',
      malloryInsight: ''
    }));
  };

  const handleSimulateMitm = async () => {
    const { shoukatKeys, hashimKeys } = insecureRefs.current;
    if (!shoukatKeys || !hashimKeys) {
      setInsecureState((prev) => ({
        ...prev,
        attackStatus: 'Generate shoukat_ and hashim_ keys first.'
      }));
      return;
    }

    const malloryKeys = await generateECDHKeyPairInsecure();
    insecureRefs.current.malloryKeys = malloryKeys;

    const malloryPublic = await exportPublicKeyBase64(malloryKeys.publicKey);

    setInsecureState((prev) => ({
      ...prev,
      malloryPublic,
      attackStatus:
        'Mallory intercepted both public keys and replaced them with her own. shoukat_ ↔ Mallory ↔ hashim_ tunnel established.'
    }));
  };

  const handleShowSharedSecrets = async () => {
    const { shoukatKeys, hashimKeys, malloryKeys } = insecureRefs.current;
    if (!shoukatKeys || !hashimKeys || !malloryKeys) {
      setInsecureState((prev) => ({
        ...prev,
        attackStatus: 'Run the previous steps before showing shared secrets.'
      }));
      return;
    }

    const sharedShoukatMallory = await deriveSharedSecretInsecure(shoukatKeys.privateKey, malloryKeys.publicKey);
    const sharedHashimMallory = await deriveSharedSecretInsecure(hashimKeys.privateKey, malloryKeys.publicKey);

    insecureRefs.current.sharedShoukatMallory = sharedShoukatMallory;
    insecureRefs.current.sharedHashimMallory = sharedHashimMallory;

    const sharedShoukatMalloryPreview =
      btoa(String.fromCharCode(...new Uint8Array(sharedShoukatMallory))).slice(0, 24) + '...';
    const sharedHashimMalloryPreview =
      btoa(String.fromCharCode(...new Uint8Array(sharedHashimMallory))).slice(0, 24) + '...';

    setInsecureState((prev) => ({
      ...prev,
      sharedShoukatMallory: sharedShoukatMalloryPreview,
      sharedHashimMallory: sharedHashimMalloryPreview,
      attackStatus: 'Both victims unknowingly share secrets with Mallory.'
    }));
  };

  const handleMalloryMessage = async () => {
    const { sharedShoukatMallory, sharedHashimMallory } = insecureRefs.current;

    if (!sharedShoukatMallory || !sharedHashimMallory) {
      setInsecureState((prev) => ({
        ...prev,
        malloryInsight: 'Derive the fake shared secrets before demonstrating decryption.'
      }));
      return;
    }

    const sampleMessage = 'Hello hashim_, here is the secret plan.';
    const intercepted = await encryptWithSharedSecret(sharedShoukatMallory, sampleMessage);
    const malloryReads = await decryptWithSharedSecret(sharedShoukatMallory, intercepted);
    const reEncrypted = await encryptWithSharedSecret(sharedHashimMallory, malloryReads);
    const receives  = await decryptWithSharedSecret(sharedHashimMallory, reEncrypted);

    setInsecureState((prev) => ({
      ...prev,
      malloryInsight: `Mallory decrypted shoukat_'s message ("${malloryReads}") and sent it to hashim_.` +
        ` hashim_ still sees: "${receives }". MITM SUCCESSFUL.`,
      attackStatus: 'Mallory can read and modify everything.'
    }));
  };

  const handleSecureDemo = async () => {
    if (!privateKey || !user?.publicKey) {
      setSecureState({
        secureStatus: '',
        mitmStatus: '',
        error: 'Load your identity key first by logging in.'
      });
      return;
    }

    try {
      const bobIdentity = await window.crypto.subtle.generateKey(
        {
          name: 'RSA-PSS',
          modulusLength: 2048,
          publicExponent: new Uint8Array([1, 0, 1]),
          hash: 'SHA-256'
        },
        true,
        ['sign', 'verify']
      );

      const bobECDH = await generateECDHKeyPairInsecure();
      const bobECDHJwk = await window.crypto.subtle.exportKey('jwk', bobECDH.publicKey);
      const bobECDHString = JSON.stringify(bobECDHJwk);

      const legitimateSignature = await signData(bobIdentity.privateKey, bobECDHString, 'RSA');
      const signatureValid = await verifySignature(bobIdentity.publicKey, legitimateSignature, bobECDHString);

      const malloryECDH = await generateECDHKeyPairInsecure();
      const malloryECDHJwk = await window.crypto.subtle.exportKey('jwk', malloryECDH.publicKey);
      const malloryECDHString = JSON.stringify(malloryECDHJwk);

      const signatureValidAfterSwap = await verifySignature(
        bobIdentity.publicKey,
        legitimateSignature,
        malloryECDHString
      );

      setSecureState({
        secureStatus: signatureValid
          ? '✅ Legitimate exchange: signature verified. Key accepted.'
          : 'Unexpected verification failure.',
        mitmStatus: signatureValidAfterSwap
          ? '⚠ MITM should have failed, but signature verification unexpectedly passed.'
          : '❌ MITM Attack Detected — Signature Verification Failed. Mallory cannot impersonate hashim_.',
        error: ''
      });
      
      if (!signatureValidAfterSwap && user) {
        try {
          await logSecurityEvent({
            username: user.username,
            eventType: 'MITM_ATTACK_DETECTED',
            details: { context: 'secure_demo', result: 'signature_verification_failed' }
          });
        } catch (logError) {
          console.error('Failed to log security event:', logError);
        }
      }
    } catch (error) {
      setSecureState({
        secureStatus: '',
        mitmStatus: '',
        error: error.message
      });
    }
  };

  if (!user) {
    return (
      <div className="page-container">
        <div className="card dashboard">
          <h1>MITM Attack Demonstration</h1>
          <p className="status-text">Please log in first to run the demo.</p>
          <Link to="/login" className="btn-secondary" style={{ marginTop: '1rem', display: 'inline-block' }}>
            Go to Login
          </Link>
        </div>
      </div>
    );
  }

  return (
    <div className="page-container">
      <div className="card dashboard">
        <h1>MITM Attack Demonstration</h1>
        <p>
          This page demonstrates why unsigned ECDH exchanges are vulnerable and how identity-key signatures from Phase 3
          block Mallory.
        </p>
        <Link to="/" className="btn-secondary" style={{ marginTop: '1rem', display: 'inline-block' }}>
          ← Back to Dashboard
        </Link>
      </div>

      <div className="card dashboard">
        <h2>1️⃣ Insecure ECDH (No Signatures)</h2>
        <p>
          shoukat_ and hashim_ exchange plain ECDH public keys. Mallory can intercept and swap keys, establishing two shared
          secrets.
        </p>
        <div className="button-group">
          <button className="btn-primary" onClick={handleGenerateInsecure}>
            Generate shoukat_ & hashim_ Keys (Insecure)
          </button>
          <button className="btn-primary" onClick={handleSimulateMitm}>
            Simulate MITM Attack
          </button>
          <button className="btn-primary" onClick={handleShowSharedSecrets}>
            Show Fake Shared Secrets
          </button>
          <button className="btn-primary" onClick={handleMalloryMessage}>
            Decrypt/Encrypt with Mallory
          </button>
        </div>
        <div className="demo-box">
          <p><strong>shoukat_ Public Key:</strong> {insecureState.shoukatPublic || '—'}</p>
          <p><strong>hashim_ Public Key:</strong> {insecureState.hashimPublic || '—'}</p>
          <p><strong>Mallory Public Key:</strong> {insecureState.malloryPublic || '—'}</p>
          <p><strong>Shared Secret (shoukat_↔Mallory):</strong> {insecureState.sharedShoukatMallory || '—'}</p>
          <p><strong>Shared Secret (hashim_↔Mallory):</strong> {insecureState.sharedHashimMallory || '—'}</p>
          <p className="status-text">{insecureState.attackStatus}</p>
          {insecureState.malloryInsight && (
            <p className="replay-warning" style={{ marginTop: '0.75rem' }}>
              {insecureState.malloryInsight}
            </p>
          )}
        </div>
      </div>

      <div className="card dashboard">
        <h2>2️⃣ Secure ECDH (Signed Keys)</h2>
        <p>
          Identity-key signatures force Mallory to forge hashim_&apos;s signature, which is impossible without his private key.
        </p>
        <div className="button-group">
          <button className="btn-primary" onClick={handleSecureDemo}>
            Start Secure Signed Key Exchange
          </button>
        </div>
        <div className="demo-box">
          {secureState.error && <p className="replay-warning">{secureState.error}</p>}
          {secureState.secureStatus && <p className="status-text">{secureState.secureStatus}</p>}
          {secureState.mitmStatus && <p className="status-text">{secureState.mitmStatus}</p>}
        </div>
        <p className="helper-text" style={{ marginTop: '1rem' }}>
          In the secure system, both parties sign their ECDH keys with long-term identity keys produced in Phase 2. Mallory
          cannot forge these signatures, so the attack fails.
        </p>
      </div>
    </div>
  );
};

export default MitmDemo;

