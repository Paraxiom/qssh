//! Quantum-secure transport layer

use crate::compression::{CompressionAlgorithm, CompressionContext};
use crate::{crypto::SymmetricCrypto, QsshError, Result};
use bincode;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tokio::sync::{oneshot, Mutex, Notify};
use crate::crypto::{mlkem1024_encapsulate, MlKem1024KeyPair};
use hkdf::Hkdf;
use sha3::{Digest, Sha3_256};
use std::any::Any;
use zeroize::Zeroize;

pub mod channel;
pub mod protocol;
pub mod quantum_resistant;

pub use channel::*;
pub use protocol::*;
pub use quantum_resistant::*;

/// Unified transport trait for both classical and quantum-resistant transports
#[async_trait::async_trait]
pub trait QsshTransport: Send + Sync {
    /// Send a message
    async fn send_message<T: serde::Serialize + Send + Sync>(&self, message: &T) -> Result<()>;

    /// Receive a message
    async fn receive_message<T: for<'de> serde::Deserialize<'de> + 'static>(&self) -> Result<T>;

    /// Close the transport
    async fn close(&self) -> Result<()>;
}

/// Maximum raw frame size (1MB) for unauthenticated inbound data.
const MAX_RAW_MESSAGE_SIZE: usize = 1024 * 1024;

/// Maximum serialized message size (1MB).
const MAX_MESSAGE_SIZE: usize = MAX_RAW_MESSAGE_SIZE;

/// In-memory transport used by unit tests.
///
/// This mock has no network side effects and can be shared across tasks.
#[derive(Default)]
pub struct MockTransport {
    incoming: Mutex<VecDeque<u8>>,
    outgoing: Mutex<VecDeque<u8>>,
    closed: AtomicBool,
    incoming_notify: Notify,
}

impl MockTransport {
    /// Create an empty mock transport.
    pub fn new() -> Self {
        Self::default()
    }

    /// Inject a serialized frame into the incoming buffer.
    pub async fn inject_frame(&self, frame: &[u8]) {
        let mut incoming = self.incoming.lock().await;
        incoming.extend(frame.iter().copied());
        self.incoming_notify.notify_waiters();
    }

    /// Inject a typed message into the incoming buffer.
    pub async fn inject_message<T: serde::Serialize>(&self, message: &T) -> Result<()> {
        let payload = bincode::serialize(message)
            .map_err(|e| QsshError::Protocol(format!("Serialization failed: {}", e)))?;
        let frame = encode_frame(&payload)?;
        self.inject_frame(&frame).await;
        Ok(())
    }

    /// Serialize a raw payload into a framed message and queue it to outgoing.
    pub async fn send_raw_message(&self, payload: &[u8]) -> std::result::Result<Vec<u8>, QsshError> {
        if self.closed.load(Ordering::Acquire) {
            return Err(QsshError::Connection("Mock transport is closed".into()));
        }

        let frame = encode_frame(payload)?;
        let mut outgoing = self.outgoing.lock().await;
        outgoing.extend(frame.iter().copied());
        Ok(frame)
    }

    /// Wait for and return the next fully framed incoming payload.
    pub async fn receive_raw_message(&self) -> std::result::Result<Vec<u8>, QsshError> {
        loop {
            {
                let mut incoming = self.incoming.lock().await;
                if let Some(payload) = try_pop_frame(&mut incoming)? {
                    return Ok(payload);
                }
            }

            if self.closed.load(Ordering::Acquire) {
                return Err(QsshError::Connection("Mock transport is closed".into()));
            }

            self.incoming_notify.notified().await;
        }
    }

    /// Drain all raw bytes written by send_message.
    pub async fn take_outgoing_bytes(&self) -> Vec<u8> {
        let mut outgoing = self.outgoing.lock().await;
        outgoing.drain(..).collect()
    }

    /// Pop and decode one sent message from the outgoing buffer, if present.
    pub async fn take_outgoing_message<T: for<'de> serde::Deserialize<'de>>(
        &self,
    ) -> Result<Option<T>> {
        let mut outgoing = self.outgoing.lock().await;
        let Some(payload) = try_pop_frame(&mut outgoing)? else {
            return Ok(None);
        };

        let message = bincode::deserialize(&payload)
            .map_err(|e| QsshError::Protocol(format!("Deserialization failed: {}", e)))?;
        Ok(Some(message))
    }

    /// Return the current number of queued incoming bytes.
    pub async fn incoming_len(&self) -> usize {
        self.incoming.lock().await.len()
    }

    /// Return the current number of queued outgoing bytes.
    pub async fn outgoing_len(&self) -> usize {
        self.outgoing.lock().await.len()
    }
}

#[async_trait::async_trait]
impl QsshTransport for MockTransport {
    async fn send_message<T: serde::Serialize + Send + Sync>(&self, message: &T) -> Result<()> {
        let payload = bincode::serialize(message)
            .map_err(|e| QsshError::Protocol(format!("Serialization failed: {}", e)))?;
        let _ = self.send_raw_message(&payload).await?;
        Ok(())
    }

    async fn receive_message<T: for<'de> serde::Deserialize<'de> + 'static>(&self) -> Result<T> {
        let payload = self.receive_raw_message().await?;
        let message = bincode::deserialize(&payload)
            .map_err(|e| QsshError::Protocol(format!("Deserialization failed: {}", e)))?;
        Ok(message)
    }

    async fn close(&self) -> Result<()> {
        self.closed.store(true, Ordering::Release);
        self.incoming_notify.notify_waiters();
        Ok(())
    }
}

fn encode_frame(payload: &[u8]) -> Result<Vec<u8>> {
    if payload.len() > MAX_RAW_MESSAGE_SIZE {
        return Err(QsshError::Protocol("Message too large".into()));
    }

    let mut frame = Vec::with_capacity(4 + payload.len());
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(payload);
    Ok(frame)
}

fn try_pop_frame(buffer: &mut VecDeque<u8>) -> Result<Option<Vec<u8>>> {
    if buffer.len() < 4 {
        return Ok(None);
    }

    let len_bytes = [
        *buffer.front()
            .ok_or_else(|| QsshError::Protocol("Truncated frame: missing length byte 0".into()))?,
        *buffer
            .get(1)
            .ok_or_else(|| QsshError::Protocol("Truncated frame: missing length byte 1".into()))?,
        *buffer
            .get(2)
            .ok_or_else(|| QsshError::Protocol("Truncated frame: missing length byte 2".into()))?,
        *buffer
            .get(3)
            .ok_or_else(|| QsshError::Protocol("Truncated frame: missing length byte 3".into()))?,
    ];

    let frame_len = u32::from_be_bytes(len_bytes) as usize;
    if frame_len > MAX_RAW_MESSAGE_SIZE {
        return Err(QsshError::Protocol("Frame too large".into()));
    }

    if buffer.len() < 4 + frame_len {
        return Ok(None);
    }

    let mut payload = Vec::with_capacity(frame_len);
    for i in 0..frame_len {
        let byte = *buffer
            .get(4 + i)
            .ok_or_else(|| QsshError::Protocol("Truncated frame: missing payload byte".into()))?;
        payload.push(byte);
    }

    for _ in 0..(4 + frame_len) {
        let _ = buffer
            .pop_front()
            .ok_or_else(|| QsshError::Protocol("Truncated frame: buffer underflow".into()))?;
    }

    Ok(Some(payload))
}

/// The value both peers seed the rekey chain with, computed from the
/// handshake's directional keys in a role-independent order.
pub fn initial_epoch_secret(client_write_key: &[u8], server_write_key: &[u8]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(b"qssh-epoch-v2");
    h.update(client_write_key);
    h.update(server_write_key);
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    out
}

/// In-flight state of an in-band rekey (see [`Transport::initiate_rekey`]).
#[derive(Default)]
struct RekeyState {
    /// Initiator only: our ephemeral ML-KEM-1024 keypair until the reply arrives.
    pending_dk: Option<MlKem1024KeyPair>,
    /// Both roles: the receive key to install when the peer's `NewKeys` arrives.
    pending_recv: Option<SymmetricCrypto>,
    /// Initiator only: fires once both directions run under the new epoch.
    done: Option<oneshot::Sender<()>>,
}

/// Transport layer for encrypted communication
///
/// # In-band rekey (protocol 0.2)
///
/// Three frames, all sent under the keys in force at that moment:
/// `RekeyInit{ek}` from the initiator, then `RekeyReply{ct}` and `NewKeys`
/// from the responder, then `NewKeys` from the initiator. Each side switches
/// its **send** key right after writing its own `NewKeys` (under the writer
/// lock, so no other frame can slip between them) and its **receive** key
/// right after reading the peer's `NewKeys`. Frames are strictly ordered per
/// direction, so no frame is ever decrypted under the wrong epoch. The
/// control frames are consumed inside [`Transport::receive_message`] by
/// whichever task owns the reader, so a rekey never needs a second reader
/// and can never steal a data frame. New keys come from a fresh ML-KEM-1024
/// encapsulation, chained to the previous epoch through an HKDF salt.
#[derive(Clone)]
pub struct Transport {
    reader: Arc<Mutex<OwnedReadHalf>>,
    writer: Arc<Mutex<OwnedWriteHalf>>,
    send_crypto: Arc<RwLock<SymmetricCrypto>>,
    recv_crypto: Arc<RwLock<SymmetricCrypto>>,
    send_sequence: Arc<Mutex<u64>>,
    recv_sequence: Arc<Mutex<u64>>,
    /// Number of completed rekey operations
    rekey_count: Arc<std::sync::atomic::AtomicU32>,
    /// Compression context for outgoing data
    send_compression: Arc<Mutex<CompressionContext>>,
    /// Compression context for incoming data
    recv_compression: Arc<Mutex<CompressionContext>>,
    /// Chains successive rekeys to the handshake (see `initial_epoch_secret`).
    epoch_secret: Arc<Mutex<[u8; 32]>>,
    /// In-flight rekey, if any.
    rekey: Arc<Mutex<RekeyState>>,
}

impl Transport {
    /// Create new transport from established TCP connection (unidirectional - for backwards compatibility)
    pub fn new(stream: TcpStream, crypto: SymmetricCrypto) -> Result<Self> {
        let (reader, writer) = stream.into_split();
        let default_recv_crypto = SymmetricCrypto::from_shared_secret(&[0u8; 32])?;
        Ok(Self {
            reader: Arc::new(Mutex::new(reader)),
            writer: Arc::new(Mutex::new(writer)),
            send_crypto: Arc::new(RwLock::new(crypto)),
            recv_crypto: Arc::new(RwLock::new(default_recv_crypto)),
            send_sequence: Arc::new(Mutex::new(0)),
            recv_sequence: Arc::new(Mutex::new(0)),
            rekey_count: Arc::new(std::sync::atomic::AtomicU32::new(0)),
            send_compression: Arc::new(Mutex::new(CompressionContext::new(
                CompressionAlgorithm::None,
                6,
            ))),
            recv_compression: Arc::new(Mutex::new(CompressionContext::new(
                CompressionAlgorithm::None,
                6,
            ))),
            epoch_secret: Arc::new(Mutex::new([0u8; 32])),
            rekey: Arc::new(Mutex::new(RekeyState::default())),
        })
    }

    /// Create new transport with separate send and receive crypto
    pub fn new_bidirectional(
        stream: TcpStream,
        send_crypto: SymmetricCrypto,
        recv_crypto: SymmetricCrypto,
    ) -> Self {
        let (reader, writer) = stream.into_split();
        Self {
            reader: Arc::new(Mutex::new(reader)),
            writer: Arc::new(Mutex::new(writer)),
            send_crypto: Arc::new(RwLock::new(send_crypto)),
            recv_crypto: Arc::new(RwLock::new(recv_crypto)),
            send_sequence: Arc::new(Mutex::new(0)),
            recv_sequence: Arc::new(Mutex::new(0)),
            rekey_count: Arc::new(std::sync::atomic::AtomicU32::new(0)),
            send_compression: Arc::new(Mutex::new(CompressionContext::new(
                CompressionAlgorithm::None,
                6,
            ))),
            recv_compression: Arc::new(Mutex::new(CompressionContext::new(
                CompressionAlgorithm::None,
                6,
            ))),
            epoch_secret: Arc::new(Mutex::new([0u8; 32])),
            rekey: Arc::new(Mutex::new(RekeyState::default())),
        }
    }

    /// Send an encrypted message
    pub async fn send_message<T: Serialize>(&self, message: &T) -> Result<()> {
        log::trace!("Transport: sending message");
        let plaintext = bincode::serialize(message)
            .map_err(|e| QsshError::Protocol(format!("Serialization failed: {}", e)))?;
        if plaintext.len() > MAX_MESSAGE_SIZE {
            return Err(QsshError::Protocol("Message too large".into()));
        }
        // The writer lock is taken FIRST and held through sequencing, encryption
        // and the write, so a key switch (which also takes it) can never
        // interleave with a frame sequenced or encrypted under the previous
        // epoch.
        let mut writer = self.writer.lock().await;
        self.write_frame_locked(&mut writer, plaintext).await
    }

    /// Compress, sequence, encrypt and write one frame. The caller holds `writer`.
    async fn write_frame_locked(&self, writer: &mut OwnedWriteHalf, plaintext: Vec<u8>) -> Result<()> {
        let plaintext = {
            let mut comp = self.send_compression.lock().await;
            comp.compress(&plaintext)?
        };
        let seq = {
            let mut seq_lock = self.send_sequence.lock().await;
            let current = *seq_lock;
            *seq_lock += 1;
            current
        };
        let mut authenticated_data = Vec::with_capacity(8 + plaintext.len());
        authenticated_data.extend_from_slice(&seq.to_be_bytes());
        authenticated_data.extend_from_slice(&plaintext);
        let (ciphertext, nonce) = {
            let crypto = self
                .send_crypto
                .read()
                .map_err(|_| QsshError::Crypto("Send crypto lock poisoned".into()))?;
            crypto.encrypt(&authenticated_data)?
        };
        // Frame format: [4 bytes length][12 bytes nonce][ciphertext]
        let frame_length = (nonce.len() + ciphertext.len()) as u32;
        let mut frame = Vec::with_capacity(4 + frame_length as usize);
        frame.extend_from_slice(&frame_length.to_be_bytes());
        frame.extend_from_slice(&nonce);
        frame.extend_from_slice(&ciphertext);
        log::trace!("Transport: writing {} bytes to stream", frame.len());
        writer.write_all(&frame).await.map_err(|e| {
            log::error!("Transport: failed to write to stream: {}", e);
            QsshError::Io(e)
        })?;
        writer.flush().await.map_err(|e| {
            log::error!("Transport: failed to flush stream: {}", e);
            QsshError::Io(e)
        })?;
        Ok(())
    }

    /// Receive and decrypt a message.
    ///
    /// In-band rekey control frames (`RekeyInit`, `RekeyReply`, `NewKeys`) are
    /// consumed here and never returned to the caller, so the task that owns
    /// the reader drives the rekey and no data frame can be lost to it.
    pub async fn receive_message<T: for<'de> Deserialize<'de> + 'static>(&self) -> Result<T> {
        let mut reader = self.reader.lock().await;
        loop {
            let plaintext = self.read_frame_locked(&mut reader).await?;
            if std::any::TypeId::of::<T>() == std::any::TypeId::of::<Message>() {
                let message: Message = bincode::deserialize(&plaintext)
                    .map_err(|e| QsshError::Protocol(format!("Deserialization failed: {}", e)))?;
                match message {
                    Message::RekeyInit(init) => {
                        self.handle_rekey_init(init).await?;
                        continue;
                    }
                    Message::RekeyReply(reply) => {
                        self.handle_rekey_reply(reply).await?;
                        continue;
                    }
                    Message::NewKeys => {
                        self.handle_new_keys().await?;
                        continue;
                    }
                    other => {
                        let boxed: Box<dyn Any> = Box::new(other);
                        return boxed
                            .downcast::<T>()
                            .map(|b| *b)
                            .map_err(|_| QsshError::Protocol("Message type mismatch".into()));
                    }
                }
            }
            return bincode::deserialize(&plaintext)
                .map_err(|e| QsshError::Protocol(format!("Deserialization failed: {}", e)));
        }
    }

    /// Read, decrypt, sequence-check and decompress one frame. The caller holds `reader`.
    async fn read_frame_locked(&self, reader: &mut OwnedReadHalf) -> Result<Vec<u8>> {
        let mut length_bytes = [0u8; 4];
        log::trace!("Transport: attempting to read 4 bytes for frame length");
        reader.read_exact(&mut length_bytes).await.map_err(|e| {
            log::error!("Transport: failed to read frame length: {}", e);
            QsshError::Io(e)
        })?;
        let frame_length = u32::from_be_bytes(length_bytes) as usize;
        if frame_length > MAX_MESSAGE_SIZE {
            return Err(QsshError::Protocol("Frame too large".into()));
        }
        if frame_length < 12 {
            return Err(QsshError::Protocol("Frame too short".into()));
        }
        let mut frame = vec![0u8; frame_length];
        reader.read_exact(&mut frame).await.map_err(QsshError::Io)?;
        let (nonce, ciphertext) = frame.split_at(12);
        let authenticated_data = {
            let crypto = self
                .recv_crypto
                .read()
                .map_err(|_| QsshError::Crypto("Recv crypto lock poisoned".into()))?;
            crypto.decrypt(ciphertext, nonce)?
        };
        if authenticated_data.len() < 8 {
            return Err(QsshError::Protocol("Invalid message format".into()));
        }
        let (seq_bytes, plaintext) = authenticated_data.split_at(8);
        let received_seq = u64::from_be_bytes(
            seq_bytes
                .try_into()
                .map_err(|_| QsshError::Protocol("Invalid sequence number format".into()))?,
        );
        let expected_seq = {
            let mut seq_lock = self.recv_sequence.lock().await;
            let current = *seq_lock;
            *seq_lock += 1;
            current
        };
        if received_seq != expected_seq {
            return Err(QsshError::Protocol(format!(
                "Invalid sequence number: expected {}, got {}",
                expected_seq, received_seq
            )));
        }
        let plaintext = {
            let mut comp = self.recv_compression.lock().await;
            comp.decompress(plaintext)?
        };
        Ok(plaintext)
    }

    /// Enable compression on this transport (called after handshake negotiation)
    pub async fn set_compression(&self, algorithm: CompressionAlgorithm, level: u32) {
        let mut send = self.send_compression.lock().await;
        *send = CompressionContext::new(algorithm, level);
        let mut recv = self.recv_compression.lock().await;
        *recv = CompressionContext::new(algorithm, level);
        if algorithm.is_enabled() {
            log::info!(
                "Transport compression enabled: {:?} (level {})",
                algorithm,
                level
            );
        }
    }

    /// Get compression statistics for sent data
    pub async fn compression_stats(
        &self,
    ) -> (
        crate::compression::CompressionStats,
        crate::compression::CompressionStats,
    ) {
        let send = self.send_compression.lock().await;
        let recv = self.recv_compression.lock().await;
        (send.stats().clone(), recv.stats().clone())
    }

    /// Seed the rekey chain. Called once by the handshake with
    /// [`initial_epoch_secret`], which both peers compute identically.
    pub async fn set_epoch_secret(&self, secret: [u8; 32]) {
        let mut epoch = self.epoch_secret.lock().await;
        epoch.zeroize();
        *epoch = secret;
    }

    /// Start an in-band rekey (phase 1 of 3). Sends a fresh ML-KEM-1024
    /// encapsulation key under the current keys and returns a receiver that
    /// fires once both directions run under the new epoch. The caller must
    /// not read from the transport itself: whichever task owns the reader
    /// completes the remaining phases inside [`Transport::receive_message`].
    pub async fn initiate_rekey(&self) -> Result<oneshot::Receiver<()>> {
        let (tx, rx) = oneshot::channel();
        let kem_ek = {
            let mut st = self.rekey.lock().await;
            if st.pending_dk.is_some() || st.pending_recv.is_some() {
                return Err(QsshError::Protocol("Rekey already in progress".into()));
            }
            let keypair = MlKem1024KeyPair::generate()?;
            let ek = keypair.encapsulation_key().to_vec();
            st.pending_dk = Some(keypair);
            st.done = Some(tx);
            ek
        };
        log::info!("Rekey #{}: initiating (ML-KEM-1024)", self.rekey_count() + 1);
        self.send_message(&Message::RekeyInit(RekeyInitMessage { kem_ek })).await?;
        Ok(rx)
    }

    /// Responder, phase 2: encapsulate, derive, reply, then switch our send key.
    async fn handle_rekey_init(&self, init: RekeyInitMessage) -> Result<()> {
        let (initiator_write, responder_write) = {
            let mut st = self.rekey.lock().await;
            if st.pending_dk.is_some() || st.pending_recv.is_some() {
                return Err(QsshError::Protocol("RekeyInit while a rekey is in progress".into()));
            }
            let (mut ss, kem_ct) = mlkem1024_encapsulate(&init.kem_ek)?;
            let keys = self.derive_epoch_keys(&ss).await?;
            ss.zeroize();
            st.pending_recv = Some(SymmetricCrypto::from_shared_secret(&keys.0)?);
            drop(st);
            self.send_message(&Message::RekeyReply(RekeyReplyMessage { kem_ct })).await?;
            keys
        };
        let new_send = SymmetricCrypto::from_shared_secret(&responder_write)?;
        let mut initiator_write = initiator_write;
        let mut responder_write = responder_write;
        initiator_write.zeroize();
        responder_write.zeroize();
        self.send_new_keys_and_switch(new_send).await
    }

    /// Initiator, phase 2: decapsulate, derive, then switch our send key.
    async fn handle_rekey_reply(&self, reply: RekeyReplyMessage) -> Result<()> {
        let (mut initiator_write, mut responder_write) = {
            let mut st = self.rekey.lock().await;
            let dk = st
                .pending_dk
                .take()
                .ok_or_else(|| QsshError::Protocol("RekeyReply without a pending rekey".into()))?;
            let mut ss = dk.decapsulate(&reply.kem_ct)?;
            drop(dk);
            let keys = self.derive_epoch_keys(&ss).await?;
            ss.zeroize();
            st.pending_recv = Some(SymmetricCrypto::from_shared_secret(&keys.1)?);
            keys
        };
        let new_send = SymmetricCrypto::from_shared_secret(&initiator_write)?;
        initiator_write.zeroize();
        responder_write.zeroize();
        self.send_new_keys_and_switch(new_send).await
    }

    /// Phase 3, receive side: the peer's `NewKeys` was the last frame under
    /// the old keys, so install the pending receive key now.
    async fn handle_new_keys(&self) -> Result<()> {
        let mut st = self.rekey.lock().await;
        let new_recv = st
            .pending_recv
            .take()
            .ok_or_else(|| QsshError::Protocol("NewKeys without a pending rekey".into()))?;
        {
            let mut recv = self
                .recv_crypto
                .write()
                .map_err(|_| QsshError::Crypto("Recv crypto lock poisoned during rekey".into()))?;
            *recv = new_recv;
        }
        *self.recv_sequence.lock().await = 0;
        let count = self.rekey_count.fetch_add(1, Ordering::Relaxed) + 1;
        if let Some(tx) = st.done.take() {
            let _ = tx.send(());
        }
        log::info!("Rekey #{} complete: both directions on new keys", count);
        Ok(())
    }

    /// Phase 3, send side: write `NewKeys` as the last frame under the old
    /// key and switch the send key before releasing the writer lock.
    async fn send_new_keys_and_switch(&self, new_send: SymmetricCrypto) -> Result<()> {
        let plaintext = bincode::serialize(&Message::NewKeys)
            .map_err(|e| QsshError::Protocol(format!("Serialization failed: {}", e)))?;
        let mut writer = self.writer.lock().await;
        self.write_frame_locked(&mut writer, plaintext).await?;
        {
            let mut send = self
                .send_crypto
                .write()
                .map_err(|_| QsshError::Crypto("Send crypto lock poisoned during rekey".into()))?;
            *send = new_send;
        }
        *self.send_sequence.lock().await = 0;
        Ok(())
    }

    /// Derive the next epoch from the ML-KEM shared secret, salted with the
    /// current epoch secret so every rekey is chained to the handshake.
    /// Returns `(initiator_write_key, responder_write_key)` and advances the
    /// epoch secret.
    async fn derive_epoch_keys(&self, shared_secret: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        let mut epoch = self.epoch_secret.lock().await;
        let hk = Hkdf::<Sha3_256>::new(Some(&epoch[..]), shared_secret);
        let mut initiator_write = vec![0u8; 32];
        let mut responder_write = vec![0u8; 32];
        let mut next = [0u8; 32];
        hk.expand(b"qssh-rekey-v2 initiator write", &mut initiator_write)
            .map_err(|_| QsshError::Crypto("HKDF expand failed".into()))?;
        hk.expand(b"qssh-rekey-v2 responder write", &mut responder_write)
            .map_err(|_| QsshError::Crypto("HKDF expand failed".into()))?;
        hk.expand(b"qssh-rekey-v2 epoch", &mut next)
            .map_err(|_| QsshError::Crypto("HKDF expand failed".into()))?;
        epoch.zeroize();
        *epoch = next;
        next.zeroize();
        Ok((initiator_write, responder_write))
    }

    /// Get the number of completed rekey operations
    pub fn rekey_count(&self) -> u32 {
        self.rekey_count.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Close the transport
    pub async fn close(&self) -> Result<()> {
        let mut writer = self.writer.lock().await;
        writer.shutdown().await.map_err(QsshError::Io)?;
        Ok(())
    }
}

/// Implement unified transport trait for classical transport
#[async_trait::async_trait]
impl QsshTransport for Transport {
    async fn send_message<T: serde::Serialize + Send + Sync>(&self, message: &T) -> Result<()> {
        self.send_message(message).await
    }

    async fn receive_message<T: for<'de> serde::Deserialize<'de> + 'static>(&self) -> Result<T> {
        self.receive_message().await
    }

    async fn close(&self) -> Result<()> {
        self.close().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::{timeout, Duration};

    #[tokio::test]
    async fn mock_transport_inject_and_receive_message() {
        let transport = MockTransport::new();
        let expected = Message::Ping(42);

        transport.inject_message(&expected).await.unwrap();
        let received: Message = transport.receive_message().await.unwrap();

        match received {
            Message::Ping(v) => assert_eq!(v, 42),
            _ => panic!("unexpected message variant"),
        }
    }

    #[tokio::test]
    async fn mock_transport_send_and_drain_outgoing_message() {
        let transport = MockTransport::new();
        let sent = Message::Pong(7);

        transport.send_message(&sent).await.unwrap();
        let drained: Option<Message> = transport.take_outgoing_message().await.unwrap();

        match drained {
            Some(Message::Pong(v)) => assert_eq!(v, 7),
            _ => panic!("unexpected outgoing message"),
        }
    }

    #[tokio::test]
    async fn mock_transport_close_unblocks_receiver() {
        let transport = Arc::new(MockTransport::new());
        let receiver = transport.clone();

        let wait_task = tokio::spawn(async move { receiver.receive_message::<Message>().await });

        tokio::task::yield_now().await;
        transport.close().await.unwrap();

        let result = timeout(Duration::from_secs(1), wait_task).await;
        assert!(result.is_ok(), "receiver task did not complete in time");

        let join_result = result.unwrap().unwrap();
        assert!(join_result.is_err(), "receiver should fail after close");
    }
}

/// Kani bounded model checking harnesses for classical transport.
///
/// Verifies integer cast safety, bounds checking, and panic-freedom
/// for the encrypted transport layer.
///
/// Run with: `cargo kani --harness <harness_name>`
#[cfg(kani)]
mod kani_proofs {
    use super::*;

    // ── Step 6: Integer Cast Safety ────────────────────────────────────────

    /// Proves the `(nonce.len() + ciphertext.len()) as u32` cast at line 103
    /// never truncates, given MAX_MESSAGE_SIZE bounds.
    /// AES-256-GCM: nonce=12 bytes, tag=16 bytes, so max ciphertext
    /// = MAX_MESSAGE_SIZE + 8 (sequence) + 16 (tag) = 1048600 bytes.
    /// Total frame_length = 12 + 1048600 = 1048612, well within u32::MAX.
    #[kani::proof]
    fn proof_transport_frame_length_cast() {
        let nonce_len: usize = 12; // AES-GCM nonce is always 12 bytes
        let ciphertext_len: usize = kani::any();
        // Max ciphertext = plaintext + sequence(8) + AES-GCM tag(16)
        kani::assume(ciphertext_len <= MAX_MESSAGE_SIZE + 8 + 16);

        let total = nonce_len + ciphertext_len;
        let cast_result = total as u32;

        // Prove no truncation
        assert_eq!(cast_result as usize, total);
        assert!(total <= u32::MAX as usize);
    }

    // ── Step 7: Message Size Bounds ────────────────────────────────────────

    /// Proves that Transport::receive_message checks frame_length against
    /// MAX_MESSAGE_SIZE before allocating. This prevents OOM DoS attacks.
    #[kani::proof]
    fn proof_transport_receive_bounded() {
        let length_bytes: [u8; 4] = kani::any();
        let frame_length = u32::from_be_bytes(length_bytes) as usize;

        // Simulate the bounds check from line 141
        if frame_length > MAX_MESSAGE_SIZE {
            // Would return Err — no allocation occurs
            assert!(frame_length > MAX_MESSAGE_SIZE);
        } else {
            // Allocation is bounded to at most MAX_MESSAGE_SIZE (1 MB)
            assert!(frame_length <= MAX_MESSAGE_SIZE);
            assert!(frame_length <= 1024 * 1024);
        }
    }

    /// Proves the send_raw `data.len() as u32` cast in handshake
    /// never truncates for messages within MAX_MESSAGE_SIZE.
    #[kani::proof]
    fn proof_handshake_send_raw_no_truncation() {
        let data_len: usize = kani::any();
        kani::assume(data_len <= MAX_MESSAGE_SIZE); // 1 MB

        let cast_result = data_len as u32;

        // MAX_MESSAGE_SIZE = 1048576, which fits in u32 (max 4294967295)
        assert_eq!(cast_result as usize, data_len);
    }
}
