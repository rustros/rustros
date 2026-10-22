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
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::server::{ServerConfig, UnbufferedServerConnection};
use rustls::unbuffered::{ConnectionState, EncodeError, EncryptError, InsufficientSizeError, UnbufferedStatus};

pub use provider::{random, seed, set_time, x25519_public};
pub use rustls::server::ServerConfig as RustlsServerConfig;

/// Whether `sig` is `public`'s Ed25519 signature of `msg`.
pub fn ed25519_verify(public: &[u8; 32], msg: &[u8], sig: &[u8]) -> bool {
    let (Ok(k), Ok(s)) = (ed25519_dalek::VerifyingKey::from_bytes(public), ed25519_dalek::Signature::from_slice(sig)) else { return false };
    k.verify_strict(msg, &s).is_ok()
}

/// One TLS connection, either side: the application moves ciphertext
/// between it and a TCP connection (`feed`, `take_outgoing`) and reads and
/// writes plaintext (`take_received`, `write`).
pub struct Tls {
    conn: Side,
    /// ciphertext received, not yet processed
    incoming: Vec<u8>,
    /// ciphertext to send
    outgoing: Vec<u8>,
    /// application data waiting for the handshake
    to_send: Vec<u8>,
    /// application data received
    received: Vec<u8>,
    pub established: bool,
    /// the peer closed (close_notify) or the connection ended
    pub closed: bool,
    pub error: Option<String>,
}

enum Side {
    Client(UnbufferedClientConnection),
    Server(UnbufferedServerConnection),
}

/// The client of earlier days: `Tls::client` under its old name.
pub type TlsClient = Tls;

/// A server's certificate chain and key (PEM), ready for connections.
pub fn server_config(cert_pem: &str, key_pem: &str) -> Result<Arc<ServerConfig>, String> {
    let chain: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(cert_pem.as_bytes()).collect::<Result<_, _>>().map_err(|e| format!("certificate: {e:?}"))?;
    if chain.is_empty() {
        return Err(String::from("no certificate in the PEM"));
    }
    let key = PrivateKeyDer::from_pem_slice(key_pem.as_bytes()).map_err(|e| format!("private key: {e:?}"))?;
    let config = ServerConfig::builder_with_details(Arc::new(provider::provider()), provider::time_provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| format!("{e}"))?
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .map_err(|e| format!("{e}"))?;
    Ok(Arc::new(config))
}

impl Tls {
    /// Start a handshake with `host` (the name the certificate must carry).
    pub fn new(host: &str) -> Result<Tls, String> {
        Tls::client(host)
    }

    pub fn client(host: &str) -> Result<Tls, String> {
        Tls::client_trusting(host, "")
    }

    /// A client that also trusts the CA certificates in `extra_roots` (PEM):
    /// a private CA, a test server's.
    pub fn client_trusting(host: &str, extra_roots: &str) -> Result<Tls, String> {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        for c in CertificateDer::pem_slice_iter(extra_roots.as_bytes()) {
            let c = c.map_err(|e| format!("CA certificate: {e:?}"))?;
            roots.add(c).map_err(|e| format!("CA certificate: {e}"))?;
        }
        let config = rustls::ClientConfig::builder_with_details(Arc::new(provider::provider()), provider::time_provider())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|e| format!("{e}"))?
            .with_root_certificates(roots)
            .with_no_client_auth();
        let name = ServerName::try_from(host.to_string()).map_err(|_| format!("bad server name '{host}'"))?;
        let conn = UnbufferedClientConnection::new(Arc::new(config), name).map_err(|e| format!("{e}"))?;
        let mut c = Tls::with(Side::Client(conn));
        c.pump();
        Ok(c)
    }

    /// The server side of a connection that just came in (`server_config`).
    pub fn server(config: Arc<ServerConfig>) -> Result<Tls, String> {
        let conn = UnbufferedServerConnection::new(config).map_err(|e| format!("{e}"))?;
        Ok(Tls::with(Side::Server(conn)))
    }

    fn with(conn: Side) -> Tls {
        Tls { conn, incoming: Vec::new(), outgoing: Vec::new(), to_send: Vec::new(), received: Vec::new(), established: false, closed: false, error: None }
    }

    /// Plaintext waiting to be encrypted (backpressure for the caller).
    pub fn pending_write(&self) -> usize {
        self.to_send.len()
    }

    /// Ciphertext from the peer.
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
            let mut io = Io { outgoing: &mut self.outgoing, to_send: &mut self.to_send, received: &mut self.received, established: &mut self.established, closed: &mut self.closed, error: &mut self.error };
            let (discard, more) = match &mut self.conn {
                Side::Client(c) => io.step(c.process_tls_records(&mut self.incoming)),
                Side::Server(c) => io.step(c.process_tls_records(&mut self.incoming)),
            };
            if discard > 0 {
                self.incoming.drain(..discard);
            }
            if !more {
                return;
            }
        }
    }
}

/// The parts of a connection a step of the state machine works on.
struct Io<'a> {
    outgoing: &'a mut Vec<u8>,
    to_send: &'a mut Vec<u8>,
    received: &'a mut Vec<u8>,
    established: &'a mut bool,
    closed: &'a mut bool,
    error: &'a mut Option<String>,
}

impl Io<'_> {
    /// One state of either side: (bytes of input used, whether to go on).
    fn step<Data>(&mut self, status: UnbufferedStatus<'_, '_, Data>) -> (usize, bool) {
        {
            let UnbufferedStatus { mut discard, state } = status;
            let state = match state {
                Ok(s) => s,
                Err(e) => {
                    *self.error = Some(format!("{e}"));
                    return (discard, false);
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
                                *self.error = Some(format!("{e}"));
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
                                *self.error = Some(format!("{err}"));
                                break;
                            }
                        }
                    }
                }
                ConnectionState::TransmitTlsData(t) => t.done(), // the caller sends `outgoing`
                ConnectionState::BlockedHandshake => more = false,
                ConnectionState::WriteTraffic(mut w) => {
                    *self.established = true;
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
                                    *self.error = Some(format!("{err}"));
                                    break;
                                }
                            }
                        }
                    }
                }
                ConnectionState::PeerClosed | ConnectionState::Closed => *self.closed = true,
                _ => more = false,
            }
            (discard, more)
        }
    }
}
