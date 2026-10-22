//! A TLS 1.3 client for RustROS applications: rustls (sans-IO, unbuffered)
//! on a RustCrypto provider, certificates checked against the Mozilla
//! roots. The application moves bytes between it and a TCP connection.
//!
//! Before use: `seed()` the random generator from the hardware, and keep
//! `set_time()` current (certificate dates).
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

mod provider;

use alloc::format;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use rustls::client::UnbufferedClientConnection;
use rustls::pki_types::ServerName;
use rustls::unbuffered::{ConnectionState, EncodeError, EncryptError, InsufficientSizeError, UnbufferedStatus};

pub use provider::{random, seed, set_time, x25519_public};

pub struct TlsClient {
    conn: UnbufferedClientConnection,
    /// ciphertext received, not yet processed
    incoming: Vec<u8>,
    /// ciphertext to send
    outgoing: Vec<u8>,
    /// application data waiting for the handshake
    to_send: Vec<u8>,
    /// application data received
    received: Vec<u8>,
    pub established: bool,
    /// the server closed (close_notify) or the connection ended
    pub closed: bool,
    pub error: Option<String>,
}

impl TlsClient {
    /// Start a handshake with `host` (the name the certificate must carry).
    pub fn new(host: &str) -> Result<TlsClient, String> {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let config = rustls::ClientConfig::builder_with_details(Arc::new(provider::provider()), provider::time_provider())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|e| format!("{e}"))?
            .with_root_certificates(roots)
            .with_no_client_auth();
        let name = ServerName::try_from(host.to_string()).map_err(|_| format!("bad server name '{host}'"))?;
        let conn = UnbufferedClientConnection::new(Arc::new(config), name).map_err(|e| format!("{e}"))?;
        let mut c = TlsClient { conn, incoming: Vec::new(), outgoing: Vec::new(), to_send: Vec::new(), received: Vec::new(), established: false, closed: false, error: None };
        c.pump();
        Ok(c)
    }

    /// Ciphertext from the server.
    pub fn feed(&mut self, data: &[u8]) {
        self.incoming.extend_from_slice(data);
        self.pump();
    }

    /// Application data to send (encrypted once the handshake allows).
    pub fn write(&mut self, data: &[u8]) {
        self.to_send.extend_from_slice(data);
        self.pump();
    }

    /// Ciphertext to put on the wire.
    pub fn take_outgoing(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.outgoing)
    }

    /// Application data that arrived.
    pub fn take_received(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.received)
    }

    fn pump(&mut self) {
        // each round makes progress or stops
        for _ in 0..64 {
            if self.error.is_some() || self.closed {
                return;
            }
            let UnbufferedStatus { mut discard, state } = self.conn.process_tls_records(&mut self.incoming);
            let state = match state {
                Ok(s) => s,
                Err(e) => {
                    self.error = Some(format!("{e}"));
                    return;
                }
            };
            let mut more = true;
            match state {
                ConnectionState::ReadTraffic(mut r) => {
                    while let Some(rec) = r.next_record() {
                        match rec {
                            Ok(rec) => {
                                discard += rec.discard;
                                self.received.extend_from_slice(rec.payload);
                            }
                            Err(e) => {
                                self.error = Some(format!("{e}"));
                                break;
                            }
                        }
                    }
                }
                ConnectionState::EncodeTlsData(mut e) => {
                    let mut buf = vec![0u8; 2048];
                    loop {
                        match e.encode(&mut buf) {
                            Ok(n) => {
                                self.outgoing.extend_from_slice(&buf[..n]);
                                break;
                            }
                            Err(EncodeError::InsufficientSize(InsufficientSizeError { required_size })) => buf.resize(required_size, 0),
                            Err(err) => {
                                self.error = Some(format!("{err}"));
                                break;
                            }
                        }
                    }
                }
                ConnectionState::TransmitTlsData(t) => t.done(), // the caller sends `outgoing`
                ConnectionState::BlockedHandshake => more = false,
                ConnectionState::WriteTraffic(mut w) => {
                    self.established = true;
                    if self.to_send.is_empty() {
                        more = false;
                    } else {
                        let mut buf = vec![0u8; self.to_send.len() + 1024];
                        loop {
                            match w.encrypt(&self.to_send, &mut buf) {
                                Ok(n) => {
                                    self.outgoing.extend_from_slice(&buf[..n]);
                                    self.to_send.clear();
                                    break;
                                }
                                Err(EncryptError::InsufficientSize(InsufficientSizeError { required_size })) => buf.resize(required_size, 0),
                                Err(err) => {
                                    self.error = Some(format!("{err}"));
                                    break;
                                }
                            }
                        }
                    }
                }
                ConnectionState::PeerClosed | ConnectionState::Closed => self.closed = true,
                _ => more = false,
            }
            if discard > 0 {
                self.incoming.drain(..discard);
            }
            if !more {
                return;
            }
        }
    }
}
