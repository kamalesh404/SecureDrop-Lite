/**
 * SecureDrop-Lite Frontend Application
 * Handles WebRTC signaling, file encryption/decryption, and chunked transfer.
 */

import {
  generateKeyPair,
  exportPublicKey,
  importPublicKey,
  deriveSharedSecret,
  hkdfSha256,
  generateSalt,
  generateSessionId,
  createAesGcmKey,
  encryptFile,
  decryptFile,
  formatBytes,
  formatSpeed
} from './crypto.js';

const CHUNK_SIZE = 64 * 1024;
const MAX_MESSAGE_SIZE = 16384; // 16 KiB max for data channel messages

// DOM Elements
const elements = {
  // Setup
  roomIdInput: document.getElementById('room-id'),
  peerNameInput: document.getElementById('peer-name'),
  createRoomBtn: document.getElementById('create-room-btn'),
  joinRoomBtn: document.getElementById('join-room-btn'),
  // Transfer
  statusEl: document.getElementById('status'),
  fileInput: document.getElementById('file-input'),
  sendBtn: document.getElementById('send-btn'),
  cancelBtn: document.getElementById('cancel-btn'),
  progressContainer: document.getElementById('progress-container'),
  progressFill: document.getElementById('progress-fill'),
  progressSent: document.getElementById('progress-sent'),
  progressSpeed: document.getElementById('progress-speed'),
  fileInfo: document.getElementById('file-info'),
  fileName: document.getElementById('file-name'),
  fileSize: document.getElementById('file-size'),
  fileChunks: document.getElementById('file-chunks'),
  sessionIdEl: document.getElementById('session-id'),
  // Receive
  receiveStatus: document.getElementById('receive-status'),
  receiveFileName: document.getElementById('receive-file-name'),
  receiveFileSize: document.getElementById('receive-file-size'),
  receiveFileChunks: document.getElementById('receive-file-chunks'),
  receiveSessionId: document.getElementById('receive-session-id'),
  receiveProgressContainer: document.getElementById('receive-progress-container'),
  receiveProgressFill: document.getElementById('receive-progress-fill'),
  receiveProgressReceived: document.getElementById('receive-progress-received'),
  receiveProgressSpeed: document.getElementById('receive-progress-speed'),
  acceptBtn: document.getElementById('accept-btn'),
  rejectBtn: document.getElementById('reject-btn'),
  // QR/Share
  qrContainer: document.getElementById('qr-container'),
  shareUrl: document.getElementById('share-url'),
  copyUrlBtn: document.getElementById('copy-url-btn'),
  // Cards
  setupCard: document.getElementById('setup-card'),
  transferCard: document.getElementById('transfer-card'),
  receiveCard: document.getElementById('receive-card'),
  qrCard: document.getElementById('qr-card'),
};

// State
const state = {
  ws: null,
  roomId: '',
  peerId: '',
  peerName: '',
  peerConnection: null,
  dataChannel: null,
  keyPair: null,
  sharedKey: null,
  sessionId: '',
  // Sending
  file: null,
  fileChunks: [],
  sentChunks: 0,
  ackedChunks: 0,
  transferStartTime: 0,
  isSender: false,
  // Receiving
  incomingFileMeta: null,
  receivedChunks: new Map(),
  receivedChunkCount: 0,
  totalChunks: 0,
  receiveStartTime: 0,
  pendingFileData: null,
};

// Utility functions
function setStatus(el, text, className) {
  el.textContent = text;
  el.className = 'status ' + className;
}

function showCard(card) {
  [elements.setupCard, elements.transferCard, elements.receiveCard, elements.qrCard]
    .forEach(c => c.classList.add('hidden'));
  card.classList.remove('hidden');
}

function generateRoomId() {
  const bytes = crypto.getRandomValues(new Uint8Array(8));
  return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
}

function getWsUrl() {
  const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
  return `${protocol}//${location.host}/ws/${state.roomId}`;
}

// WebRTC Configuration
const rtcConfig = {
  iceServers: [
    { urls: 'stun:stun.l.google.com:19302' },
    { urls: 'stun:stun1.l.google.com:19302' },
  ],
  iceCandidatePoolSize: 10,
};

// Signaling
async function connectSignaling() {
  const ws = new WebSocket(getWsUrl());
  state.ws = ws;

  ws.onopen = () => {
    setStatus(elements.statusEl, 'Connected to signaling server', 'connected');
  };

  ws.onmessage = async (event) => {
    try {
      const msg = JSON.parse(event.data);
      await handleSignalingMessage(msg);
    } catch (e) {
      console.error('Signaling message error:', e);
    }
  };

  ws.onclose = () => {
    setStatus(elements.statusEl, 'Disconnected from signaling server', 'error');
    cleanup();
  };

  ws.onerror = (err) => {
    console.error('WebSocket error:', err);
    setStatus(elements.statusEl, 'Signaling connection error', 'error');
  };
}

async function handleSignalingMessage(msg) {
  switch (msg.type) {
    case 'welcome':
      state.peerId = msg.peer_id;
      updatePeerIdDisplay();
      break;
    case 'peer-joined':
      if (msg.peer_id !== state.peerId) {
        await handlePeerJoined(msg.peer_id);
      }
      break;
    case 'peer-left':
      handlePeerLeft(msg.peer_id);
      break;
    case 'offer':
      await handleOffer(msg.from, msg.offer);
      break;
    case 'answer':
      await handleAnswer(msg.from, msg.answer);
      break;
    case 'ice-candidate':
      await handleIceCandidate(msg.from, msg.candidate);
      break;
    case 'file-meta':
      handleFileMeta(msg);
      break;
    case 'file-chunk':
      await handleFileChunk(msg);
      break;
    case 'chunk-ack':
      handleChunkAck(msg);
      break;
    case 'transfer-complete':
      handleTransferComplete(msg);
      break;
    case 'transfer-cancel':
      handleTransferCancel();
      break;
  }
}

function sendSignaling(msg) {
  if (state.ws && state.ws.readyState === WebSocket.OPEN) {
    state.ws.send(JSON.stringify(msg));
  }
}

// WebRTC Peer Connection
async function createPeerConnection(remotePeerId) {
  const pc = new RTCPeerConnection(rtcConfig);

  pc.onicecandidate = (event) => {
    if (event.candidate) {
      sendSignaling({
        type: 'ice-candidate',
        candidate: event.candidate.toJSON(),
        target: remotePeerId,
      });
    }
  };

  pc.onconnectionstatechange = () => {
    console.log('Connection state:', pc.connectionState);
    if (pc.connectionState === 'connected') {
      setStatus(elements.statusEl, 'WebRTC connected - E2E encrypted', 'connected');
    } else if (pc.connectionState === 'disconnected' || pc.connectionState === 'failed') {
      setStatus(elements.statusEl, 'WebRTC disconnected', 'error');
    }
  };

  return pc;
}

async function handlePeerJoined(remotePeerId) {
  console.log('Peer joined:', remotePeerId);
  state.peerConnection = await createPeerConnection(remotePeerId);

  // Create data channel
  state.dataChannel = state.peerConnection.createDataChannel('file-transfer', {
    ordered: true,
    maxRetransmits: 0,
  });
  setupDataChannel(state.dataChannel);

  // Create offer
  const offer = await state.peerConnection.createOffer();
  await state.peerConnection.setLocalDescription(offer);
  sendSignaling({ type: 'offer', offer: offer.toJSON(), target: remotePeerId });
}

async function handleOffer(from, offer) {
  console.log('Received offer from:', from);
  state.peerConnection = await createPeerConnection(from);

  state.peerConnection.ondatachannel = (event) => {
    state.dataChannel = event.channel;
    setupDataChannel(state.dataChannel);
  };

  await state.peerConnection.setRemoteDescription(new RTCSessionDescription(offer));
  const answer = await state.peerConnection.createAnswer();
  await state.peerConnection.setLocalDescription(answer);
  sendSignaling({ type: 'answer', answer: answer.toJSON(), target: from });
}

async function handleAnswer(from, answer) {
  console.log('Received answer from:', from);
  await state.peerConnection.setRemoteDescription(new RTCSessionDescription(answer));
}

async function handleIceCandidate(from, candidate) {
  try {
    await state.peerConnection.addIceCandidate(new RTCIceCandidate(candidate));
  } catch (e) {
    console.error('ICE candidate error:', e);
  }
}

function handlePeerLeft(peerId) {
  console.log('Peer left:', peerId);
  if (state.dataChannel) {
    state.dataChannel.close();
    state.dataChannel = null;
  }
  if (state.peerConnection) {
    state.peerConnection.close();
    state.peerConnection = null;
  }
  setStatus(elements.statusEl, 'Peer disconnected', 'error');
  showCard(elements.setupCard);
  resetTransferState();
}

// Data Channel
function setupDataChannel(channel) {
  channel.binaryType = 'arraybuffer';

  channel.onopen = () => {
    console.log('Data channel open');
    // Perform key exchange
    performKeyExchange();
  };

  channel.onclose = () => {
    console.log('Data channel closed');
  };

  channel.onerror = (err) => {
    console.error('Data channel error:', err);
  };

  channel.onmessage = (event) => {
    handleDataChannelMessage(event.data);
  };
}

async function performKeyExchange() {
  // Generate ephemeral key pair for this session
  state.keyPair = await generateKeyPair();
  const publicKeyRaw = await exportPublicKey(state.keyPair.publicKey);

  // Send our public key
  sendDataChannel({
    type: 'key-exchange',
    publicKey: Array.from(publicKeyRaw),
    sessionId: state.sessionId,
  });
}

async function handleDataChannelMessage(data) {
  const msg = JSON.parse(new TextDecoder().decode(data));

  switch (msg.type) {
    case 'key-exchange':
      await handleKeyExchange(msg);
      break;
    case 'key-exchange-ack':
      handleKeyExchangeAck();
      break;
    case 'file-meta':
      handleIncomingFileMeta(msg);
      break;
    case 'file-chunk':
      await handleIncomingFileChunk(msg);
      break;
    case 'chunk-ack':
      handleIncomingChunkAck(msg);
      break;
    case 'transfer-complete':
      handleIncomingTransferComplete();
      break;
    case 'transfer-cancel':
      handleIncomingTransferCancel();
      break;
  }
}

function sendDataChannel(msg) {
  if (state.dataChannel && state.dataChannel.readyState === 'open') {
    state.dataChannel.send(JSON.stringify(msg));
  }
}

async function handleKeyExchange(msg) {
  const peerPublicKey = await importPublicKey(new Uint8Array(msg.publicKey));
  const sharedSecret = await deriveSharedSecret(state.keyPair.privateKey, peerPublicKey);

  // Derive encryption key using HKDF
  const salt = msg.salt || generateSalt();
  const info = new TextEncoder().encode('securedrop-lite-file-transfer');
  const keyMaterial = await hkdfSha256(sharedSecret, salt, info);
  state.sharedKey = await createAesGcmKey(keyMaterial);

  // Send acknowledgment with salt
  sendDataChannel({
    type: 'key-exchange-ack',
    salt: Array.from(salt),
  });
}

function handleKeyExchangeAck() {
  console.log('Key exchange complete');
  if (state.isSender && state.file) {
    startFileTransfer();
  }
}

async function handleIncomingFileMeta(msg) {
  state.incomingFileMeta = msg;
  state.totalChunks = msg.totalChunks;
  state.receivedChunks.clear();
  state.receivedChunkCount = 0;
  state.receiveStartTime = performance.now();

  elements.receiveFileName.textContent = msg.fileName;
  elements.receiveFileSize.textContent = formatBytes(msg.fileSize);
  elements.receiveFileChunks.textContent = msg.totalChunks;
  elements.receiveSessionId.textContent = msg.sessionId;
  elements.receiveProgressContainer.style.display = 'block';
  elements.acceptBtn.disabled = false;
  elements.rejectBtn.disabled = false;
  setStatus(elements.receiveStatus, `Incoming: ${msg.fileName} (${formatBytes(msg.fileSize)})`, 'connecting');
  showCard(elements.receiveCard);
}

async function handleIncomingFileChunk(msg) {
  if (!state.sharedKey) return;

  const chunkData = new Uint8Array(msg.data);
  const chunkIndex = msg.index;

  try {
    const decrypted = await decryptChunk(state.sharedKey, chunkData, chunkIndex);
    state.receivedChunks.set(chunkIndex, decrypted);
    state.receivedChunkCount++;

    // Send acknowledgment
    sendDataChannel({ type: 'chunk-ack', index: chunkIndex });

    // Update progress
    const received = Array.from(state.receivedChunks.values()).reduce((a, b) => a + b.length, 0);
    const elapsed = (performance.now() - state.receiveStartTime) / 1000;
    const speed = elapsed > 0 ? received / elapsed : 0;
    const progress = (state.receivedChunkCount / state.totalChunks) * 100;

    elements.receiveProgressFill.style.width = `${progress}%`;
    elements.receiveProgressReceived.textContent = formatBytes(received);
    elements.receiveProgressSpeed.textContent = formatSpeed(speed);
  } catch (e) {
    console.error('Chunk decryption failed:', e);
    sendDataChannel({ type: 'chunk-nack', index: chunkIndex });
  }
}

function handleIncomingChunkAck(msg) {
  state.ackedChunks++;
  updateSendProgress();
}

function handleIncomingTransferComplete() {
  setStatus(elements.receiveStatus, 'Transfer complete - assembling file...', 'connected');
  assembleReceivedFile();
}

function handleIncomingTransferCancel() {
  setStatus(elements.receiveStatus, 'Transfer cancelled by sender', 'error');
  resetReceiveState();
}

// File Transfer - Sender
function handleFileSelect(event) {
  const file = event.target.files[0];
  if (!file) return;

  state.file = file;
  state.sessionId = generateSessionId();
  state.fileChunks = [];
  state.sentChunks = 0;
  state.ackedChunks = 0;
  state.transferStartTime = performance.now();

  elements.fileName.textContent = file.name;
  elements.fileSize.textContent = formatBytes(file.size);
  elements.fileChunks.textContent = Math.ceil(file.size / CHUNK_SIZE);
  elements.sessionIdEl.textContent = state.sessionId;
  elements.fileInfo.classList.add('show');
  elements.sendBtn.disabled = false;

  // Pre-encrypt file
  encryptFileForTransfer(file);
}

async function encryptFileForTransfer(file) {
  setStatus(elements.statusEl, 'Encrypting file...', 'connecting');
  elements.progressContainer.style.display = 'block';

  const arrayBuffer = await file.arrayBuffer();
  const fileData = new Uint8Array(arrayBuffer);
  state.fileChunks = await encryptFile(state.sharedKey, fileData);

  setStatus(elements.statusEl, 'File encrypted - ready to send', 'connected');
}

function startFileTransfer() {
  if (!state.file || state.fileChunks.length === 0) return;

  state.isSender = true;
  elements.progressContainer.style.display = 'block';
  elements.sendBtn.disabled = true;
  elements.cancelBtn.disabled = false;
  elements.fileInput.disabled = true;

  // Send file metadata
  sendDataChannel({
    type: 'file-meta',
    fileName: state.file.name,
    fileSize: state.file.size,
    totalChunks: state.fileChunks.length,
    sessionId: state.sessionId,
    mimeType: state.file.type,
  });

  // Send chunks
  sendNextChunk();
}

function sendNextChunk() {
  if (state.sentChunks >= state.fileChunks.length) {
    // All chunks sent, wait for acks
    return;
  }

  // Check buffer
  if (state.dataChannel.bufferedAmount > MAX_MESSAGE_SIZE * 10) {
    setTimeout(sendNextChunk, 10);
    return;
  }

  const chunk = state.fileChunks[state.sentChunks];
  sendDataChannel({
    type: 'file-chunk',
    index: state.sentChunks,
    data: Array.from(chunk),
  });
  state.sentChunks++;
  updateSendProgress();

  // Send next chunk
  if (state.sentChunks < state.fileChunks.length) {
    setTimeout(sendNextChunk, 0);
  }
}

function updateSendProgress() {
  const total = state.fileChunks.length;
  const sent = state.ackedChunks;
  const progress = total > 0 ? (sent / total) * 100 : 0;

  const elapsed = (performance.now() - state.transferStartTime) / 1000;
  const sentBytes = state.fileChunks.slice(0, sent).reduce((a, b) => a + b.length, 0);
  const speed = elapsed > 0 ? sentBytes / elapsed : 0;

  elements.progressFill.style.width = `${progress}%`;
  elements.progressSent.textContent = formatBytes(sentBytes);
  elements.progressSpeed.textContent = formatSpeed(speed);

  if (sent >= total) {
    completeTransfer();
  }
}

function completeTransfer() {
  sendDataChannel({ type: 'transfer-complete', sessionId: state.sessionId });
  setStatus(elements.statusEl, 'Transfer complete!', 'connected');
  elements.sendBtn.disabled = true;
  elements.cancelBtn.disabled = true;
  elements.fileInput.disabled = false;
  elements.fileInput.value = '';
}

function cancelTransfer() {
  sendDataChannel({ type: 'transfer-cancel', sessionId: state.sessionId });
  resetTransferState();
  setStatus(elements.statusEl, 'Transfer cancelled', 'idle');
}

function resetTransferState() {
  state.file = null;
  state.fileChunks = [];
  state.sentChunks = 0;
  state.ackedChunks = 0;
  state.isSender = false;
  elements.progressContainer.style.display = 'none';
  elements.progressFill.style.width = '0%';
  elements.fileInfo.classList.remove('show');
  elements.sendBtn.disabled = true;
  elements.cancelBtn.disabled = true;
  elements.fileInput.disabled = false;
}

// File Transfer - Receiver
function acceptFile() {
  elements.acceptBtn.disabled = true;
  elements.rejectBtn.disabled = true;
  setStatus(elements.receiveStatus, 'Receiving file...', 'connected');
}

function rejectFile() {
  sendDataChannel({ type: 'transfer-cancel' });
  resetReceiveState();
  showCard(elements.transferCard);
  setStatus(elements.receiveStatus, 'File rejected', 'idle');
}

function resetReceiveState() {
  state.incomingFileMeta = null;
  state.receivedChunks.clear();
  state.receivedChunkCount = 0;
  state.totalChunks = 0;
  state.pendingFileData = null;
  elements.receiveProgressContainer.style.display = 'none';
  elements.receiveProgressFill.style.width = '0%';
  elements.acceptBtn.disabled = true;
  elements.rejectBtn.disabled = true;
}

async function assembleReceivedFile() {
  if (!state.incomingFileMeta || !state.sharedKey) return;

  try {
    // Sort chunks by index
    const sortedChunks = [];
    for (let i = 0; i < state.totalChunks; i++) {
      const chunk = state.receivedChunks.get(i);
      if (!chunk) {
        throw new Error(`Missing chunk ${i}`);
      }
      sortedChunks.push(chunk);
    }

    const fileData = await decryptFile(state.sharedKey, sortedChunks);

    // Create blob and download
    const blob = new Blob([fileData], { type: state.incomingFileMeta.mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = state.incomingFileMeta.fileName;
    a.click();
    URL.revokeObjectURL(url);

    setStatus(elements.receiveStatus, 'File saved successfully!', 'connected');
    resetReceiveState();
    showCard(elements.transferCard);
  } catch (e) {
    console.error('File assembly failed:', e);
    setStatus(elements.receiveStatus, 'Failed to assemble file: ' + e.message, 'error');
  }
}

// UI Event Handlers
elements.createRoomBtn.addEventListener('click', () => {
  state.roomId = elements.roomIdInput.value.trim() || generateRoomId();
  state.peerName = elements.peerNameInput.value.trim() || 'Anonymous';
  elements.roomIdInput.value = state.roomId;
  initRoom();
});

elements.joinRoomBtn.addEventListener('click', () => {
  state.roomId = elements.roomIdInput.value.trim();
  state.peerName = elements.peerNameInput.value.trim() || 'Anonymous';
  if (!state.roomId) {
    alert('Please enter a room ID');
    return;
  }
  initRoom();
});

async function initRoom() {
  state.sessionId = generateRoomId();
  await connectSignaling();
  showCard(elements.transferCard);
  showCard(elements.qrCard);
  updateShareUrl();
}

function updateShareUrl() {
  const url = `${location.origin}/?room=${state.roomId}`;
  elements.shareUrl.value = url;

  // Generate QR code using a simple API
  const qrUrl = `https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=${encodeURIComponent(url)}`;
  elements.qrContainer.innerHTML = `<img src="${qrUrl}" alt="Room QR Code">`;
}

elements.copyUrlBtn.addEventListener('click', async () => {
  await navigator.clipboard.writeText(elements.shareUrl.value);
  const original = elements.copyUrlBtn.textContent;
  elements.copyUrlBtn.textContent = 'Copied!';
  setTimeout(() => elements.copyUrlBtn.textContent = original, 2000);
});

elements.fileInput.addEventListener('change', handleFileSelect);
elements.sendBtn.addEventListener('click', () => {
  if (state.sharedKey) {
    startFileTransfer();
  } else {
    setStatus(elements.statusEl, 'Waiting for key exchange...', 'connecting');
  }
});
elements.cancelBtn.addEventListener('click', cancelTransfer);
elements.acceptBtn.addEventListener('click', acceptFile);
elements.rejectBtn.addEventListener('click', rejectFile);

// Handle URL parameter for joining
const urlParams = new URLSearchParams(window.location.search);
const roomParam = urlParams.get('room');
if (roomParam) {
  elements.roomIdInput.value = roomParam;
  elements.joinRoomBtn.click();
}

function updatePeerIdDisplay() {
  // Could show peer ID somewhere if needed
  console.log('My peer ID:', state.peerId);
}

function cleanup() {
  if (state.dataChannel) {
    state.dataChannel.close();
    state.dataChannel = null;
  }
  if (state.peerConnection) {
    state.peerConnection.close();
    state.peerConnection = null;
  }
  if (state.ws) {
    state.ws.close();
    state.ws = null;
  }
}

window.addEventListener('beforeunload', cleanup);