import axios from 'axios';

const api = axios.create({
  baseURL: 'http://localhost:5000/api/v1'
});

export const registerUser = (data) => {
  return api.post('/auth/register', data);
};

export const loginUser = (data) => {
  return api.post('/auth/login', data);
};

export const createKeyExchangeRequest = (data) => {
  return api.post('/keyexchange/request', data);
};

export const getPendingKeyExchangeRequests = (username) => {
  return api.get(`/keyexchange/pending/${username}`);
};

export const createKeyExchangeResponse = (data) => {
  return api.post('/keyexchange/response', data);
};

export const getKeyExchangeResponse = (username) => {
  return api.get(`/keyexchange/response/${username}`);
};

export const createKeyExchangeConfirm = (data) => {
  return api.post('/keyexchange/confirm', data);
};

export const getKeyExchangeConfirm = (username) => {
  return api.get(`/keyexchange/confirm/${username}`);
};

export const getUserByUsername = (username) => {
  return api.get(`/auth/user/${username}`);
};

export const getAllUsers = () => {
  return api.get('/auth/users');
};

export const sendMessage = (data) => {
  return api.post('/messages/send', data);
};

export const getMessages = (username, otherUser) => {
  return api.get('/messages', {
    params: { username, otherUser }
  });
};

export const deleteKeyExchangeRequest = (requesterUsername, targetUsername) => {
  return api.delete('/keyexchange/request', {
    data: { requesterUsername, targetUsername }
  });
};

export const uploadEncryptedFile = (data) => {
  return api.post('/files/upload', data);
};

export const getFileList = (userUsername, peerUsername) => {
  return api.get('/files', {
    params: {
      user: userUsername,
      peer: peerUsername
    }
  });
};

export const downloadEncryptedFile = (fileId) => {
  return api.get(`/files/${fileId}`);
};

export const logSecurityEvent = (payload) => {
  return api.post('/audit/log', payload);
};

export const getAuditLogs = (username) => {
  return api.get(`/audit/${username}`);
};

export default api;


