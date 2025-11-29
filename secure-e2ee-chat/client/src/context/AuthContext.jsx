import { createContext, useContext, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { registerUser, loginUser, logSecurityEvent } from '../services/apiService';
import {
  generateIdentityKeyPair,
  exportPublicKeyJWK,
  exportPrivateKeyJWK,
  deriveKeyFromPassword,
  encryptPrivateKeyWithAES,
  decryptPrivateKeyWithAES
} from '../utils/cryptoUtils';
import { storePrivateKey, retrievePrivateKey } from '../utils/indexedDBUtils';

const AuthContext = createContext(null);

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [keyStatus, setKeyStatus] = useState('');
  const [privateKey, setPrivateKey] = useState(null);
  const navigate = useNavigate();

  const handleRegister = async ({ username, password, confirmPassword }) => {
    try {
      setLoading(true);
      setError(null);
      setKeyStatus('');

      const { publicKey, privateKey: generatedPrivateKey, keyAlgorithm } = await generateIdentityKeyPair('RSA');
      const publicJwk = await exportPublicKeyJWK(publicKey);
      const privateJwk = await exportPrivateKeyJWK(generatedPrivateKey);

      const { key: aesKey, salt, iterations } = await deriveKeyFromPassword(password);
      const encryptedBundle = await encryptPrivateKeyWithAES(privateJwk, aesKey, salt, iterations);

      const response = await registerUser({
        username,
        password,
        confirmPassword,
        publicKey: JSON.stringify(publicJwk),
        keyAlgorithm
      });

      await storePrivateKey(username, encryptedBundle);
      setUser(response.data.user);
      setPrivateKey(generatedPrivateKey);
      setKeyStatus('Identity Key Generated & Stored Securely');
      
      try {
        await logSecurityEvent({
          username,
          eventType: 'IDENTITY_KEY_GENERATED',
          details: { keyAlgorithm }
        });
      } catch (logError) {
        console.error('Failed to log security event:', logError);
      }
      
      navigate('/dashboard');
      return response.data;
    } catch (err) {
      const message = err.response?.data?.message || err.message || 'Registration failed';
      setError(message);
      throw new Error(message);
    } finally {
      setLoading(false);
    }
  };

  const handleLogin = async ({ username, password }) => {
    try {
      setLoading(true);
      setError(null);
      setKeyStatus('');

      const response = await loginUser({ username, password });
      setUser(response.data.user);

      try {
        await logSecurityEvent({
          username,
          eventType: 'LOGIN_SUCCESS',
          details: {}
        });
      } catch (logError) {
        console.error('Failed to log security event:', logError);
      }

      const encryptedBundle = await retrievePrivateKey(username);
      if (!encryptedBundle) {
        setKeyStatus('No identity key found for this user');
        navigate('/dashboard');
        return response.data;
      }

      const { key: aesKey } = await deriveKeyFromPassword(password, encryptedBundle.salt);
      const importedPrivateKey = await decryptPrivateKeyWithAES(encryptedBundle, aesKey);
      setPrivateKey(importedPrivateKey);
      setKeyStatus('Identity Key Loaded');

      try {
        await logSecurityEvent({
          username,
          eventType: 'IDENTITY_KEY_LOADED',
          details: {}
        });
      } catch (logError) {
        console.error('Failed to log security event:', logError);
      }

      navigate('/dashboard');
      return response.data;
    } catch (err) {
      const message = err.response?.data?.message || err.message || 'Login failed';
      setError(message);
      throw new Error(message);
    } finally {
      setLoading(false);
    }
  };

  const cleanupPrivateKey = () => {
    if (privateKey) {
      setPrivateKey(null);
    }
  };

  const logout = async () => {
    const currentUsername = user?.username;
    cleanupPrivateKey();
    setUser(null);
    setKeyStatus('');
    
    if (currentUsername) {
      try {
        await logSecurityEvent({
          username: currentUsername,
          eventType: 'LOGOUT',
          details: {}
        });
      } catch (logError) {
        console.error('Failed to log security event:', logError);
      }
    }
    
    navigate('/login');
  };

  const value = {
    user,
    loading,
    error,
    keyStatus,
    privateKey,
    register: handleRegister,
    login: handleLogin,
    logout,
    setError,
    setKeyStatus
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

export const useAuth = () => useContext(AuthContext);

