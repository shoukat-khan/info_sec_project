import { useEffect, useRef, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { useKeyExchange } from '../context/KeyExchangeContext';
import { getAllUsers, getMessages, logSecurityEvent, getAuditLogs } from '../services/apiService';

const Dashboard = () => {
  const { user, keyStatus } = useAuth();
  const {
    keyExchangeStatus,
    pendingRequests,
    sessionKey,
    outgoingSequence,
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
    resetSession
  } = useKeyExchange();
  const navigate = useNavigate();
  const [targetUsername, setTargetUsername] = useState('');
  const [availableUsers, setAvailableUsers] = useState([]);
  const [loadingUsers, setLoadingUsers] = useState(false);
  const [messageText, setMessageText] = useState('');
  const [messages, setMessages] = useState([]);
  const [replayWarning, setReplayWarning] = useState('');
  const [chatUser, setChatUser] = useState('');
  const [selectedFile, setSelectedFile] = useState(null);
  const [auditLogs, setAuditLogs] = useState([]);
  const [loadingAuditLogs, setLoadingAuditLogs] = useState(false);
  const processedMessageIdsRef = useRef(new Set());

  useEffect(() => {
    if (!user) {
      navigate('/login');
    }
  }, [user, navigate]);

  const { privateKey } = useAuth();
  
  useEffect(() => {
    if (user && !privateKey) {
      navigate('/login', { state: { error: 'Identity key missing. Please log in again.' } });
    }
  }, [user, privateKey, navigate]);

  const handleLoadUsers = async () => {
    try {
      setLoadingUsers(true);
      const response = await getAllUsers();
      const users = response.data.users.filter((u) => u !== user.username);
      setAvailableUsers(users);
    } catch (error) {
      alert(`Error loading users: ${error.message}`);
    } finally {
      setLoadingUsers(false);
    }
  };

  const handleSelectUser = (username) => {
    setTargetUsername(username);
  };

  if (!user) {
    return null;
  }

  const handleInitiate = async () => {
    if (!targetUsername.trim()) {
      alert('Please enter a target username');
      return;
    }
    try {
      await initiateKeyExchange(targetUsername.trim());
    } catch (error) {
      const errorMessage = error.response?.data?.error || error.message || 'Key exchange failed. Please try again.';
      alert(`Error: ${errorMessage}`);
    }
  };

  const handleLoadRequests = async () => {
    try {
      await loadPendingKeyExchangeRequests();
    } catch (error) {
      alert(`Error: ${error.message}`);
    }
  };

  const handleRespond = async (request) => {
    try {
      await respondToKeyExchange(request);
      await loadPendingKeyExchangeRequests();
      setTargetUsername(request.requesterUsername);
    } catch (error) {
      alert(`Error: ${error.message}`);
    }
  };

  const handlePollResponse = async () => {
    try {
      await pollForResponse();
    } catch (error) {
      alert(`Error: ${error.message}`);
    }
  };

  const handlePollConfirm = async () => {
    try {
      await pollForConfirm();
    } catch (error) {
      alert(`Error: ${error.message}`);
    }
  };

  const handleStartChat = async () => {
    if (!sessionKey) {
      alert('Please establish a session key first');
      return;
    }

    const chatPartner = sessionPartner || targetUsername.trim();
    if (!chatPartner) {
      alert('Please select a user to chat with or wait for session to be established');
      return;
    }

    processedMessageIdsRef.current = new Set();
    setMessages([]);
    setChatUser(chatPartner);
    setTargetUsername(chatPartner);
    await loadMessages({ reset: true, chatPartner });
  };

  const loadMessages = async (options = {}) => {
    const { reset = false, chatPartner = chatUser } = options;
    if (!chatPartner) return;

    if (reset) {
      processedMessageIdsRef.current = new Set();
      setMessages([]);
    }

    try {
      const response = await getMessages(user.username, chatPartner);
      const currentMessages = reset ? [] : [...messages];

      for (const msg of response.data.messages) {
        if (processedMessageIdsRef.current.has(msg._id)) {
          continue;
        }
        processedMessageIdsRef.current.add(msg._id);

        try {
          const decrypted = await receiveEncryptedMessage(
            {
              sender: msg.sender,
              receiver: msg.receiver,
              ciphertext: msg.ciphertext,
              iv: msg.iv,
              nonce: msg.nonce,
              sequence: msg.sequence,
              timestamp: msg.timestamp
            },
            { skipReplayChecks: msg.sender === user.username }
          );
          currentMessages.push({
            ...decrypted,
            id: msg._id,
            createdAt: msg.createdAt
          });
        } catch (error) {
          if (error.message.includes('Replay attack')) {
            setReplayWarning(`Replay attack detected in message from ${msg.sender}`);
            currentMessages.push({
              plaintext: '[REPLAY ATTACK BLOCKED]',
              sender: msg.sender,
              sequence: msg.sequence,
              timestamp: msg.timestamp,
              isReplay: true,
              id: msg._id
            });
            try {
              await logSecurityEvent({
                username: user.username,
                eventType: 'REPLAY_ATTACK_BLOCKED',
                details: { sender: msg.sender, sequence: msg.sequence, reason: 'message_load_check' }
              });
            } catch (logError) {
              console.error('Failed to log security event:', logError);
            }
          } else {
            currentMessages.push({
              plaintext: '[DECRYPTION ERROR]',
              sender: msg.sender,
              sequence: msg.sequence,
              timestamp: msg.timestamp,
              id: msg._id
            });
          }
        }
      }

      setMessages(
        currentMessages.sort((a, b) => {
          if (a.sequence === b.sequence) {
            return a.timestamp - b.timestamp;
          }
          return a.sequence - b.sequence;
        })
      );
    } catch (error) {
      alert(`Error loading messages: ${error.message}`);
    }
  };

  const handleSendMessage = async () => {
    if (!messageText.trim() || !chatUser || !sessionKey) {
      return;
    }
    if (!sessionReady) {
      alert('Session not ready. Please complete key exchange confirmation.');
      return;
    }
    try {
      setReplayWarning('');
      await sendEncryptedMessage(chatUser, messageText.trim());
      setMessageText('');
      await loadMessages();
    } catch (error) {
      if (error.message.includes('Replay attack')) {
        setReplayWarning('Replay attack detected! Message not sent.');
        try {
          await logSecurityEvent({
            username: user.username,
            eventType: 'REPLAY_ATTACK_BLOCKED',
            details: { reason: 'outgoing_message_check', receiver: chatUser }
          });
        } catch (logError) {
          console.error('Failed to log security event:', logError);
        }
      } else {
        const errorMessage = error.message || 'Network error — please retry.';
        alert(`Error sending message: ${errorMessage}`);
      }
    }
  };

  const handleFileSelect = (e) => {
    const file = e.target.files[0];
    if (file) {
      setSelectedFile(file);
    }
  };

  const handleSendFile = async () => {
    if (!selectedFile) {
      alert('Please select a file first');
      return;
    }

    if (!sessionKey || !sessionReady) {
      alert('Session not ready. Please complete key exchange confirmation.');
      return;
    }

    const fileReceiver = sessionPartner || chatUser;
    if (!fileReceiver) {
      alert('No session partner available. Please establish a session first.');
      return;
    }

    try {
      await sendEncryptedFile(selectedFile, fileReceiver);
      setSelectedFile(null);
      const fileInput = document.getElementById('fileInput');
      if (fileInput) {
        fileInput.value = '';
      }
    } catch (error) {
      const errorMessage = error.message || 'File upload failed. Please try again.';
      alert(`Error sending file: ${errorMessage}`);
    }
  };

  const handleLoadFiles = async () => {
    const filePeer = sessionPartner || chatUser;
    if (!filePeer) {
      alert('No session partner available');
      return;
    }

    try {
      await loadFileList(filePeer);
    } catch (error) {
      alert(`Error loading files: ${error.message}`);
    }
  };

  const handleDownloadFile = async (fileId) => {
    try {
      await downloadAndDecryptFile(fileId);
    } catch (error) {
      const errorMessage = error.message || 'Decryption failed — invalid session key.';
      alert(`Error downloading file: ${errorMessage}`);
    }
  };

  const handleResetSession = () => {
    if (window.confirm('Are you sure you want to reset the secure session? This will clear all session keys and require a new key exchange.')) {
      resetSession();
      setChatUser('');
      setMessages([]);
      setFileList([]);
      alert('Session has been reset. Please initiate new key exchange.');
    }
  };

  const formatFileSize = (bytes) => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
  };

  const handleLoadAuditLogs = async () => {
    if (!user) {
      alert('Please log in first');
      return;
    }

    try {
      setLoadingAuditLogs(true);
      const response = await getAuditLogs(user.username);
      setAuditLogs(response.data.logs || []);
    } catch (error) {
      alert(`Error loading audit logs: ${error.message}`);
    } finally {
      setLoadingAuditLogs(false);
    }
  };

  const formatEventType = (eventType) => {
    return eventType.replace(/_/g, ' ').replace(/\b\w/g, (l) => l.toUpperCase());
  };

  const formatDetails = (details) => {
    if (!details || Object.keys(details).length === 0) {
      return 'No additional details';
    }
    return JSON.stringify(details, null, 2);
  };

  return (
    <div className="page-container">
      <div className="card dashboard">
        <h1>Dashboard</h1>
        <p>Welcome, {user.username}</p>
        {keyStatus && <p className="status-text">{keyStatus}</p>}
        <div className="helper-links">
          <Link to="/mitm-demo" className="btn-secondary">
            MITM Attack Demo →
          </Link>
        </div>
      </div>

      <div className="card dashboard">
        <h2>Key Exchange (ECDH + Signatures)</h2>
        
        <div className="form-group">
          <label htmlFor="targetUsername">Target Username</label>
          <div style={{ display: 'flex', gap: '0.5rem' }}>
            <input
              id="targetUsername"
              type="text"
              value={targetUsername}
              onChange={(e) => setTargetUsername(e.target.value)}
              placeholder="Enter username to exchange keys with"
              style={{ flex: 1 }}
            />
            <button
              className="btn-primary"
              onClick={handleLoadUsers}
              disabled={loadingUsers}
              style={{ width: 'auto', padding: '0.6rem 1rem', marginTop: 0 }}
            >
              {loadingUsers ? 'Loading...' : 'Load Users'}
            </button>
          </div>
        </div>

        {availableUsers.length > 0 && (
          <div className="users-list">
            <h3>Available Users:</h3>
            <div className="users-grid">
              {availableUsers.map((username) => (
                <button
                  key={username}
                  className={`user-chip ${targetUsername === username ? 'selected' : ''}`}
                  onClick={() => handleSelectUser(username)}
                >
                  {username}
                </button>
              ))}
            </div>
          </div>
        )}

        <div className="button-group">
          <button 
            className="btn-primary" 
            onClick={handleInitiate}
            disabled={keyExchangeInProgress}
          >
            {keyExchangeInProgress ? 'Key Exchange In Progress...' : 'Start Key Exchange'}
          </button>
          {keyExchangeInProgress && (
            <p className="helper-text" style={{ color: '#93c5fd', marginTop: '0.5rem' }}>
              A key exchange is already in progress
            </p>
          )}
          <button className="btn-primary" onClick={handleLoadRequests}>
            Load Pending Requests
          </button>
          <button className="btn-primary" onClick={handlePollResponse}>
            Poll Responses
          </button>
          <button className="btn-primary" onClick={handlePollConfirm}>
            Poll Confirms
          </button>
        </div>

        {keyExchangeStatus && (
          <div className="status-box">
            <strong>Status:</strong> {keyExchangeStatus}
          </div>
        )}

        {sessionKey && (
          <div className="status-box success">
            <strong>✓ Session Key Established</strong>
          </div>
        )}

        {pendingRequests.length > 0 && (
          <div className="requests-list">
            <h3>Pending Requests:</h3>
            {pendingRequests.map((req, idx) => (
              <div key={idx} className="request-item">
                <p>
                  <strong>From:</strong> {req.requesterUsername}
                </p>
                <button
                  className="btn-primary"
                  onClick={() => handleRespond(req)}
                >
                  Respond
                </button>
              </div>
            ))}
          </div>
        )}
      </div>

      {sessionKey && !sessionReady && (
        <div className="card dashboard">
          <h2>Encrypted Messaging</h2>
          <p className="status-text">
            Complete key confirmation to unlock chat with{' '}
            <strong>{sessionPartner || targetUsername || 'your partner'}</strong>.
          </p>
          <ul className="instructions-list">
            <li>If you initiated the exchange: click <strong>Poll Responses</strong> then <strong>Poll Confirms</strong>.</li>
            <li>If you responded: click <strong>Poll Confirms</strong> to acknowledge KEY-CONFIRM-A.</li>
          </ul>
          <p className="status-text">Chat box will appear automatically after confirmation succeeds.</p>
        </div>
      )}

      {sessionKey && sessionReady && (
        <div className="card dashboard">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
            <h2>Encrypted Messaging (Replay Protected)</h2>
            <button 
              className="btn-secondary" 
              onClick={handleResetSession}
              style={{ width: 'auto', padding: '0.5rem 1rem', fontSize: '0.85rem' }}
            >
              Reset Session
            </button>
          </div>
          
          {replayWarning && (
            <div className="replay-warning">
              <strong>⚠ Replay Attack Blocked:</strong> {replayWarning}
            </div>
          )}

          {!chatUser ? (
            <div>
              <p>Session key established with: <strong>{sessionPartner || targetUsername || 'No partner'}</strong></p>
              <p>Click below to start chatting.</p>
              <button className="btn-primary" onClick={handleStartChat} disabled={!sessionKey}>
                Start Chat with {sessionPartner || targetUsername || 'Session Partner'}
              </button>
            </div>
          ) : (
            <div className="chat-container">
              <div className="chat-header">
                <h3>Chat with {chatUser}</h3>
                <p className="sequence-info">Outgoing Sequence: {outgoingSequence}</p>
              </div>

              <div className="messages-container">
                {messages.map((msg, idx) => (
                  <div key={idx} className={`message-item ${msg.sender === user.username ? 'sent' : 'received'} ${msg.isReplay ? 'replay' : ''}`}>
                    <div className="message-header">
                      <strong>{msg.sender === user.username ? 'You' : msg.sender}</strong>
                      <span className="message-meta">
                        <span className="timestamp-badge">Seq: {msg.sequence}</span>
                        <span className="timestamp-badge">{new Date(msg.timestamp).toLocaleTimeString()}</span>
                      </span>
                    </div>
                    <div className="message-content">{msg.plaintext}</div>
                    {msg.isReplay && (
                      <div className="replay-badge">REPLAY ATTACK</div>
                    )}
                  </div>
                ))}
              </div>

              <div className="message-input-group">
                <textarea
                  value={messageText}
                  onChange={(e) => setMessageText(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' && !e.shiftKey) {
                      e.preventDefault();
                      handleSendMessage();
                    }
                  }}
                  placeholder="Type a message..."
                  className="message-input"
                  rows={3}
                  disabled={!sessionReady || !sessionPartner}
                />
                <button 
                  className="btn-primary" 
                  onClick={handleSendMessage} 
                  style={{ width: 'auto', padding: '0.6rem 1.25rem' }}
                  disabled={!sessionReady || !sessionPartner || !messageText.trim()}
                >
                  Send
                </button>
                <button className="btn-secondary" onClick={loadMessages}>
                  Refresh
                </button>
              </div>
              {(!sessionReady || !sessionPartner) && (
                <p className="helper-text" style={{ marginTop: '0.5rem', color: '#fca5a5' }}>
                  Please establish a secure session before sending messages.
                </p>
              )}
            </div>
          )}
        </div>
      )}

      {sessionKey && sessionReady && (
        <div className="card dashboard">
          <h2>Encrypted File Sharing</h2>
          
          {fileStatus && (
            <div className="status-box">
              <strong>File Status:</strong> {fileStatus}
            </div>
          )}

          {(!sessionReady || !sessionPartner) && (
            <div className="replay-warning" style={{ backgroundColor: 'rgba(239, 68, 68, 0.1)', borderColor: 'rgba(239, 68, 68, 0.3)' }}>
              <strong>⚠ Session Not Ready:</strong> Please establish a secure session before sharing files.
            </div>
          )}

          <div className="form-group">
            <label htmlFor="fileInput">Select File to Send</label>
            <input
              id="fileInput"
              type="file"
              onChange={handleFileSelect}
              disabled={!sessionPartner || !sessionReady}
            />
            {selectedFile && (
              <p className="helper-text">
                Selected: {selectedFile.name} ({formatFileSize(selectedFile.size)})
              </p>
            )}
          </div>

          <div className="button-group">
            <button
              className="btn-primary"
              onClick={handleSendFile}
              disabled={!selectedFile || !sessionPartner || !sessionReady}
            >
              Send Encrypted File
            </button>
            <button
              className="btn-primary"
              onClick={handleLoadFiles}
              disabled={!sessionPartner}
            >
              Load Files with {sessionPartner || 'Session Partner'}
            </button>
          </div>

          {fileList.length > 0 && (
            <div className="files-list" style={{ marginTop: '1.5rem' }}>
              <h3>Shared Files:</h3>
              <div className="files-container">
                {fileList.map((file) => (
                  <div key={file._id} className="file-item">
                    <div className="file-info">
                      <strong>{file.filename}</strong>
                      <span className="file-meta">
                        {formatFileSize(file.filesize)} | {file.mimeType}
                      </span>
                      <span className="file-meta">
                        From: {file.sender} | {new Date(file.timestamp).toLocaleString()}
                      </span>
                    </div>
                    <button
                      className="btn-primary"
                      onClick={() => handleDownloadFile(file._id)}
                      style={{ width: 'auto', padding: '0.5rem 1rem' }}
                    >
                      Download & Decrypt
                    </button>
                  </div>
                ))}
              </div>
            </div>
          )}

          {fileList.length === 0 && sessionPartner && (
            <p className="helper-text" style={{ marginTop: '1rem' }}>
              No files shared yet. Select a file and click "Send Encrypted File" to share.
            </p>
          )}
        </div>
      )}

      <div className="card dashboard">
        <h2>Security Event Logs</h2>
        <p className="helper-text" style={{ marginBottom: '1rem' }}>
          View your security event audit logs. Only metadata is logged; no plaintext messages, keys, or sensitive data.
        </p>
        
        <div className="button-group">
          <button
            className="btn-primary"
            onClick={handleLoadAuditLogs}
            disabled={loadingAuditLogs || !user}
          >
            {loadingAuditLogs ? 'Loading...' : 'Load Audit Logs'}
          </button>
        </div>

        {auditLogs.length > 0 && (
          <div className="audit-logs-container" style={{ marginTop: '1.5rem' }}>
            <h3>Recent Events ({auditLogs.length})</h3>
            <div className="audit-logs-list">
              {auditLogs.map((log, idx) => (
                <div key={idx} className="audit-log-item">
                  <div className="audit-log-header">
                    <strong className="audit-event-type">{formatEventType(log.eventType)}</strong>
                    <span className="audit-timestamp">
                      {new Date(log.timestamp).toLocaleString()}
                    </span>
                  </div>
                  <div className="audit-log-details">
                    <pre>{formatDetails(log.details)}</pre>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {auditLogs.length === 0 && !loadingAuditLogs && (
          <p className="helper-text" style={{ marginTop: '1rem' }}>
            No audit logs loaded. Click "Load Audit Logs" to view your security events.
          </p>
        )}
      </div>
    </div>
  );
};

export default Dashboard;


