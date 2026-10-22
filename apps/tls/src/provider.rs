//! A rustls crypto provider from the RustCrypto crates: TLS 1.3 with
//! AES-GCM and ChaCha20-Poly1305, X25519 and P-256 key exchange, and RSA
//! (PKCS#1 and PSS), ECDSA (P-256, P-384) and Ed25519 signature checks for
//! certificates and handshakes.

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use aead::{AeadInPlace, KeyInit};
use rand_chacha::ChaCha20Rng;
use rand_core::{CryptoRng, RngCore, SeedableRng};
use rustls::crypto::cipher::{
    AeadKey, BorrowedPayload, InboundOpaqueMessage, InboundPlainMessage, Iv, MessageDecrypter, MessageEncrypter, Nonce, OutboundOpaqueMessage, OutboundPlainMessage,
    PrefixedPayload, Tls13AeadAlgorithm, UnsupportedOperationError, make_tls13_aad,
};
use rustls::crypto::{ActiveKeyExchange, CryptoProvider, GetRandomFailed, KeyProvider, SecureRandom, SharedSecret, SupportedKxGroup, WebPkiSupportedAlgorithms, hash, hmac, tls13::HkdfUsingHmac};
use rustls::pki_types::{AlgorithmIdentifier, InvalidSignature, PrivateKeyDer, SignatureVerificationAlgorithm, UnixTime, alg_id};
use rustls::sign::SigningKey;
use rustls::{CipherSuite, CipherSuiteCommon, ConnectionTrafficSecrets, ContentType, NamedGroup, ProtocolVersion, SignatureScheme, SupportedCipherSuite, Tls13CipherSuite};
use sha2::Digest;
use spin::Mutex;

// ---------------------------------------------------------------- randomness

static RNG: Mutex<Option<ChaCha20Rng>> = Mutex::new(None);

/// Seed (or reseed) the generator, from the hardware's random numbers.
pub fn seed(seed: [u8; 32]) {
    let mut g = RNG.lock();
    let mut s = seed;
    if let Some(old) = g.as_mut() {
        // keep what was there in the mix
        let mut prev = [0u8; 32];
        old.fill_bytes(&mut prev);
        for (a, b) in s.iter_mut().zip(prev) {
            *a ^= b;
        }
    }
    *g = Some(ChaCha20Rng::from_seed(s));
}

fn fill(buf: &mut [u8]) -> Result<(), GetRandomFailed> {
    RNG.lock().as_mut().map(|r| r.fill_bytes(buf)).ok_or(GetRandomFailed)
}

/// Random bytes from the (seeded) generator: false if it was never seeded.
pub fn random(buf: &mut [u8]) -> bool {
    fill(buf).is_ok()
}

/// The X25519 public key of a private one (WireGuard keys).
pub fn x25519_public(private: [u8; 32]) -> [u8; 32] {
    x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(private)).to_bytes()
}

/// The generator for key generation in the RustCrypto crates.
struct Rng;
impl RngCore for Rng {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.fill_bytes(&mut b);
        u32::from_le_bytes(b)
    }
    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.fill_bytes(&mut b);
        u64::from_le_bytes(b)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let _ = fill(dest);
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        fill(dest).map_err(|_| rand_core::Error::from(core::num::NonZeroU32::new(rand_core::Error::CUSTOM_START).unwrap()))
    }
}
impl CryptoRng for Rng {}

#[derive(Debug)]
struct Random;
impl SecureRandom for Random {
    fn fill(&self, buf: &mut [u8]) -> Result<(), GetRandomFailed> {
        fill(buf)
    }
}

// ---------------------------------------------------------------- time

static NOW: AtomicU64 = AtomicU64::new(0);

/// Tell the provider the time (seconds since 1970); 0: unknown.
pub fn set_time(unix: u64) {
    NOW.store(unix, Ordering::Relaxed);
}

#[derive(Debug)]
struct Clock;
impl rustls::time_provider::TimeProvider for Clock {
    fn current_time(&self) -> Option<UnixTime> {
        match NOW.load(Ordering::Relaxed) {
            0 => None,
            t => Some(UnixTime::since_unix_epoch(core::time::Duration::from_secs(t))),
        }
    }
}

pub fn time_provider() -> Arc<dyn rustls::time_provider::TimeProvider> {
    Arc::new(Clock)
}

// ---------------------------------------------------------------- hashes

struct Hash<D>(core::marker::PhantomData<D>, hash::HashAlgorithm);
static SHA256: Hash<sha2::Sha256> = Hash(core::marker::PhantomData, hash::HashAlgorithm::SHA256);
static SHA384: Hash<sha2::Sha384> = Hash(core::marker::PhantomData, hash::HashAlgorithm::SHA384);

impl<D: Digest + Clone + Send + Sync + 'static> hash::Hash for Hash<D> {
    fn start(&self) -> Box<dyn hash::Context> {
        Box::new(HashContext(D::new()))
    }
    fn hash(&self, data: &[u8]) -> hash::Output {
        hash::Output::new(&D::digest(data)[..])
    }
    fn algorithm(&self) -> hash::HashAlgorithm {
        self.1
    }
    fn output_len(&self) -> usize {
        <D as Digest>::output_size()
    }
}

struct HashContext<D>(D);
impl<D: Digest + Clone + Send + Sync + 'static> hash::Context for HashContext<D> {
    fn fork_finish(&self) -> hash::Output {
        hash::Output::new(&self.0.clone().finalize()[..])
    }
    fn fork(&self) -> Box<dyn hash::Context> {
        Box::new(HashContext(self.0.clone()))
    }
    fn finish(self: Box<Self>) -> hash::Output {
        hash::Output::new(&self.0.finalize()[..])
    }
    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }
}

struct Hmac<D>(core::marker::PhantomData<D>);
static HMAC_SHA256: Hmac<sha2::Sha256> = Hmac(core::marker::PhantomData);
static HMAC_SHA384: Hmac<sha2::Sha384> = Hmac(core::marker::PhantomData);

impl<D> hmac::Hmac for Hmac<D>
where
    D: Digest + Clone + Send + Sync + 'static + ::hmac::digest::core_api::BlockSizeUser,
    ::hmac::SimpleHmac<D>: ::hmac::Mac + Clone + Send + Sync,
{
    fn with_key(&self, key: &[u8]) -> Box<dyn hmac::Key> {
        Box::new(HmacKey(<::hmac::SimpleHmac<D> as ::hmac::Mac>::new_from_slice(key).expect("any key length")))
    }
    fn hash_output_len(&self) -> usize {
        <D as Digest>::output_size()
    }
}

struct HmacKey<M>(M);
impl<M: ::hmac::Mac + Clone + Send + Sync + 'static> hmac::Key for HmacKey<M> {
    fn sign_concat(&self, first: &[u8], middle: &[&[u8]], last: &[u8]) -> hmac::Tag {
        let mut m = self.0.clone();
        m.update(first);
        for x in middle {
            m.update(x);
        }
        m.update(last);
        hmac::Tag::new(&m.finalize().into_bytes()[..])
    }
    fn tag_len(&self) -> usize {
        <M as ::hmac::digest::OutputSizeUser>::output_size()
    }
}

// ---------------------------------------------------------------- AEADs

struct Aead<C>(core::marker::PhantomData<C>, fn(AeadKey, Iv) -> ConnectionTrafficSecrets);
static AES128: Aead<aes_gcm::Aes128Gcm> = Aead(core::marker::PhantomData, |key, iv| ConnectionTrafficSecrets::Aes128Gcm { key, iv });
static AES256: Aead<aes_gcm::Aes256Gcm> = Aead(core::marker::PhantomData, |key, iv| ConnectionTrafficSecrets::Aes256Gcm { key, iv });
static CHACHA: Aead<chacha20poly1305::ChaCha20Poly1305> = Aead(core::marker::PhantomData, |key, iv| ConnectionTrafficSecrets::Chacha20Poly1305 { key, iv });

/// AEAD tag length (16 for all three).
const TAG: usize = 16;

impl<C: KeyInit + AeadInPlace + Send + Sync + 'static> Tls13AeadAlgorithm for Aead<C> {
    fn encrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageEncrypter> {
        Box::new(Cipher(C::new_from_slice(key.as_ref()).expect("key length"), iv))
    }
    fn decrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageDecrypter> {
        Box::new(Cipher(C::new_from_slice(key.as_ref()).expect("key length"), iv))
    }
    fn key_len(&self) -> usize {
        C::key_size()
    }
    fn extract_keys(&self, key: AeadKey, iv: Iv) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        Ok((self.1)(key, iv))
    }
}

struct Cipher<C>(C, Iv);

impl<C: AeadInPlace + Send + Sync> MessageEncrypter for Cipher<C> {
    fn encrypt(&mut self, m: OutboundPlainMessage<'_>, seq: u64) -> Result<OutboundOpaqueMessage, rustls::Error> {
        let total = self.encrypted_payload_len(m.payload.len());
        let mut payload = PrefixedPayload::with_capacity(total);
        payload.extend_from_chunks(&m.payload);
        payload.extend_from_slice(&m.typ.to_array());
        let nonce = aead::Nonce::<C>::clone_from_slice(&Nonce::new(&self.1, seq).0);
        self.0
            .encrypt_in_place(&nonce, &make_tls13_aad(total), &mut EncryptBuf(&mut payload))
            .map_err(|_| rustls::Error::EncryptError)?;
        Ok(OutboundOpaqueMessage::new(ContentType::ApplicationData, ProtocolVersion::TLSv1_2, payload))
    }
    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + 1 + TAG
    }
}

impl<C: AeadInPlace + Send + Sync> MessageDecrypter for Cipher<C> {
    fn decrypt<'a>(&mut self, mut m: InboundOpaqueMessage<'a>, seq: u64) -> Result<InboundPlainMessage<'a>, rustls::Error> {
        let payload = &mut m.payload;
        let nonce = aead::Nonce::<C>::clone_from_slice(&Nonce::new(&self.1, seq).0);
        let aad = make_tls13_aad(payload.len());
        self.0.decrypt_in_place(&nonce, &aad, &mut DecryptBuf(payload)).map_err(|_| rustls::Error::DecryptError)?;
        m.into_tls13_unpadded_message()
    }
}

struct EncryptBuf<'a>(&'a mut PrefixedPayload);
impl AsRef<[u8]> for EncryptBuf<'_> {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}
impl AsMut<[u8]> for EncryptBuf<'_> {
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut()
    }
}
impl aead::Buffer for EncryptBuf<'_> {
    fn extend_from_slice(&mut self, other: &[u8]) -> aead::Result<()> {
        self.0.extend_from_slice(other);
        Ok(())
    }
    fn truncate(&mut self, len: usize) {
        self.0.truncate(len)
    }
}

struct DecryptBuf<'a, 'p>(&'a mut BorrowedPayload<'p>);
impl AsRef<[u8]> for DecryptBuf<'_, '_> {
    fn as_ref(&self) -> &[u8] {
        self.0
    }
}
impl AsMut<[u8]> for DecryptBuf<'_, '_> {
    fn as_mut(&mut self) -> &mut [u8] {
        self.0
    }
}
impl aead::Buffer for DecryptBuf<'_, '_> {
    fn extend_from_slice(&mut self, _: &[u8]) -> aead::Result<()> {
        Err(aead::Error) // decryption only shrinks
    }
    fn truncate(&mut self, len: usize) {
        self.0.truncate(len)
    }
}

// ---------------------------------------------------------------- cipher suites

static HKDF_SHA256: HkdfUsingHmac<'static> = HkdfUsingHmac(&HMAC_SHA256);
static HKDF_SHA384: HkdfUsingHmac<'static> = HkdfUsingHmac(&HMAC_SHA384);

static TLS13_AES_128_GCM_SHA256: Tls13CipherSuite = Tls13CipherSuite {
    common: CipherSuiteCommon { suite: CipherSuite::TLS13_AES_128_GCM_SHA256, hash_provider: &SHA256, confidentiality_limit: 1 << 24 },
    hkdf_provider: &HKDF_SHA256,
    aead_alg: &AES128,
    quic: None,
};
static TLS13_AES_256_GCM_SHA384: Tls13CipherSuite = Tls13CipherSuite {
    common: CipherSuiteCommon { suite: CipherSuite::TLS13_AES_256_GCM_SHA384, hash_provider: &SHA384, confidentiality_limit: 1 << 24 },
    hkdf_provider: &HKDF_SHA384,
    aead_alg: &AES256,
    quic: None,
};
static TLS13_CHACHA20_POLY1305_SHA256: Tls13CipherSuite = Tls13CipherSuite {
    common: CipherSuiteCommon { suite: CipherSuite::TLS13_CHACHA20_POLY1305_SHA256, hash_provider: &SHA256, confidentiality_limit: u64::MAX },
    hkdf_provider: &HKDF_SHA256,
    aead_alg: &CHACHA,
    quic: None,
};

// ---------------------------------------------------------------- key exchange

#[derive(Debug)]
struct X25519;
impl SupportedKxGroup for X25519 {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, rustls::Error> {
        let secret = x25519_dalek::EphemeralSecret::random_from_rng(Rng);
        let public = x25519_dalek::PublicKey::from(&secret);
        Ok(Box::new(X25519Kx(secret, public)))
    }
    fn name(&self) -> NamedGroup {
        NamedGroup::X25519
    }
}
struct X25519Kx(x25519_dalek::EphemeralSecret, x25519_dalek::PublicKey);
impl ActiveKeyExchange for X25519Kx {
    fn complete(self: Box<Self>, peer: &[u8]) -> Result<SharedSecret, rustls::Error> {
        let peer: [u8; 32] = peer.try_into().map_err(|_| rustls::Error::from(rustls::PeerMisbehaved::InvalidKeyShare))?;
        let s = self.0.diffie_hellman(&peer.into());
        if !s.was_contributory() {
            return Err(rustls::PeerMisbehaved::InvalidKeyShare.into());
        }
        Ok(SharedSecret::from(&s.as_bytes()[..]))
    }
    fn pub_key(&self) -> &[u8] {
        self.1.as_bytes()
    }
    fn group(&self) -> NamedGroup {
        NamedGroup::X25519
    }
}

#[derive(Debug)]
struct P256;
impl SupportedKxGroup for P256 {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, rustls::Error> {
        let secret = p256::ecdh::EphemeralSecret::random(&mut Rng);
        let public = p256::EncodedPoint::from(secret.public_key()).as_bytes().to_vec();
        Ok(Box::new(P256Kx(secret, public)))
    }
    fn name(&self) -> NamedGroup {
        NamedGroup::secp256r1
    }
}
struct P256Kx(p256::ecdh::EphemeralSecret, Vec<u8>);
impl ActiveKeyExchange for P256Kx {
    fn complete(self: Box<Self>, peer: &[u8]) -> Result<SharedSecret, rustls::Error> {
        let peer = p256::PublicKey::from_sec1_bytes(peer).map_err(|_| rustls::Error::from(rustls::PeerMisbehaved::InvalidKeyShare))?;
        Ok(SharedSecret::from(&self.0.diffie_hellman(&peer).raw_secret_bytes()[..]))
    }
    fn pub_key(&self) -> &[u8] {
        &self.1
    }
    fn group(&self) -> NamedGroup {
        NamedGroup::secp256r1
    }
}

// ---------------------------------------------------------------- signatures

#[derive(Debug)]
enum Rsa {
    Pkcs1Sha256,
    Pkcs1Sha384,
    Pkcs1Sha512,
    PssSha256,
    PssSha384,
    PssSha512,
}

impl SignatureVerificationAlgorithm for Rsa {
    fn verify_signature(&self, public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<(), InvalidSignature> {
        use rsa::pkcs1::DecodeRsaPublicKey;
        use signature::Verifier;
        let key = rsa::RsaPublicKey::from_pkcs1_der(public_key).map_err(|_| InvalidSignature)?;
        let sig = rsa::pkcs1v15::Signature::try_from(signature).map_err(|_| InvalidSignature)?;
        let pss = rsa::pss::Signature::try_from(signature).map_err(|_| InvalidSignature)?;
        let ok = match self {
            Rsa::Pkcs1Sha256 => rsa::pkcs1v15::VerifyingKey::<sha2::Sha256>::new(key).verify(message, &sig),
            Rsa::Pkcs1Sha384 => rsa::pkcs1v15::VerifyingKey::<sha2::Sha384>::new(key).verify(message, &sig),
            Rsa::Pkcs1Sha512 => rsa::pkcs1v15::VerifyingKey::<sha2::Sha512>::new(key).verify(message, &sig),
            Rsa::PssSha256 => rsa::pss::VerifyingKey::<sha2::Sha256>::new(key).verify(message, &pss),
            Rsa::PssSha384 => rsa::pss::VerifyingKey::<sha2::Sha384>::new(key).verify(message, &pss),
            Rsa::PssSha512 => rsa::pss::VerifyingKey::<sha2::Sha512>::new(key).verify(message, &pss),
        };
        ok.map_err(|_| InvalidSignature)
    }
    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::RSA_ENCRYPTION
    }
    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        match self {
            Rsa::Pkcs1Sha256 => alg_id::RSA_PKCS1_SHA256,
            Rsa::Pkcs1Sha384 => alg_id::RSA_PKCS1_SHA384,
            Rsa::Pkcs1Sha512 => alg_id::RSA_PKCS1_SHA512,
            Rsa::PssSha256 => alg_id::RSA_PSS_SHA256,
            Rsa::PssSha384 => alg_id::RSA_PSS_SHA384,
            Rsa::PssSha512 => alg_id::RSA_PSS_SHA512,
        }
    }
}

/// ECDSA: (curve, digest).
#[derive(Debug)]
enum Ecdsa {
    P256Sha256,
    P256Sha384,
    P384Sha256,
    P384Sha384,
}

impl SignatureVerificationAlgorithm for Ecdsa {
    fn verify_signature(&self, public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<(), InvalidSignature> {
        use signature::hazmat::PrehashVerifier;
        let digest: Vec<u8> = match self {
            Ecdsa::P256Sha256 | Ecdsa::P384Sha256 => sha2::Sha256::digest(message).to_vec(),
            Ecdsa::P256Sha384 | Ecdsa::P384Sha384 => sha2::Sha384::digest(message).to_vec(),
        };
        let ok = match self {
            Ecdsa::P256Sha256 | Ecdsa::P256Sha384 => {
                let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(public_key).map_err(|_| InvalidSignature)?;
                let sig = p256::ecdsa::Signature::from_der(signature).map_err(|_| InvalidSignature)?;
                key.verify_prehash(&digest, &sig)
            }
            Ecdsa::P384Sha256 | Ecdsa::P384Sha384 => {
                let key = p384::ecdsa::VerifyingKey::from_sec1_bytes(public_key).map_err(|_| InvalidSignature)?;
                let sig = p384::ecdsa::Signature::from_der(signature).map_err(|_| InvalidSignature)?;
                key.verify_prehash(&digest, &sig)
            }
        };
        ok.map_err(|_| InvalidSignature)
    }
    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        match self {
            Ecdsa::P256Sha256 | Ecdsa::P256Sha384 => alg_id::ECDSA_P256,
            Ecdsa::P384Sha256 | Ecdsa::P384Sha384 => alg_id::ECDSA_P384,
        }
    }
    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        match self {
            Ecdsa::P256Sha256 | Ecdsa::P384Sha256 => alg_id::ECDSA_SHA256,
            Ecdsa::P256Sha384 | Ecdsa::P384Sha384 => alg_id::ECDSA_SHA384,
        }
    }
}

#[derive(Debug)]
struct Ed25519;
impl SignatureVerificationAlgorithm for Ed25519 {
    fn verify_signature(&self, public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<(), InvalidSignature> {
        let key: [u8; 32] = public_key.try_into().map_err(|_| InvalidSignature)?;
        let key = ed25519_dalek::VerifyingKey::from_bytes(&key).map_err(|_| InvalidSignature)?;
        let sig = ed25519_dalek::Signature::from_slice(signature).map_err(|_| InvalidSignature)?;
        key.verify_strict(message, &sig).map_err(|_| InvalidSignature)
    }
    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::ED25519
    }
    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::ED25519
    }
}

static RSA_PKCS1_SHA256: Rsa = Rsa::Pkcs1Sha256;
static RSA_PKCS1_SHA384: Rsa = Rsa::Pkcs1Sha384;
static RSA_PKCS1_SHA512: Rsa = Rsa::Pkcs1Sha512;
static RSA_PSS_SHA256: Rsa = Rsa::PssSha256;
static RSA_PSS_SHA384: Rsa = Rsa::PssSha384;
static RSA_PSS_SHA512: Rsa = Rsa::PssSha512;
static ECDSA_P256_SHA256: Ecdsa = Ecdsa::P256Sha256;
static ECDSA_P256_SHA384: Ecdsa = Ecdsa::P256Sha384;
static ECDSA_P384_SHA256: Ecdsa = Ecdsa::P384Sha256;
static ECDSA_P384_SHA384: Ecdsa = Ecdsa::P384Sha384;
static ED25519: Ed25519 = Ed25519;

static ALGORITHMS: WebPkiSupportedAlgorithms = WebPkiSupportedAlgorithms {
    all: &[
        &ECDSA_P256_SHA256,
        &ECDSA_P256_SHA384,
        &ECDSA_P384_SHA256,
        &ECDSA_P384_SHA384,
        &ED25519,
        &RSA_PSS_SHA256,
        &RSA_PSS_SHA384,
        &RSA_PSS_SHA512,
        &RSA_PKCS1_SHA256,
        &RSA_PKCS1_SHA384,
        &RSA_PKCS1_SHA512,
    ],
    mapping: &[
        (SignatureScheme::ECDSA_NISTP384_SHA384, &[&ECDSA_P384_SHA384, &ECDSA_P256_SHA384]),
        (SignatureScheme::ECDSA_NISTP256_SHA256, &[&ECDSA_P256_SHA256, &ECDSA_P384_SHA256]),
        (SignatureScheme::ED25519, &[&ED25519]),
        (SignatureScheme::RSA_PSS_SHA512, &[&RSA_PSS_SHA512]),
        (SignatureScheme::RSA_PSS_SHA384, &[&RSA_PSS_SHA384]),
        (SignatureScheme::RSA_PSS_SHA256, &[&RSA_PSS_SHA256]),
        (SignatureScheme::RSA_PKCS1_SHA512, &[&RSA_PKCS1_SHA512]),
        (SignatureScheme::RSA_PKCS1_SHA384, &[&RSA_PKCS1_SHA384]),
        (SignatureScheme::RSA_PKCS1_SHA256, &[&RSA_PKCS1_SHA256]),
    ],
};

// ---------------------------------------------------------------- the provider

#[derive(Debug)]
struct NoKeys;
impl KeyProvider for NoKeys {
    fn load_private_key(&self, _key: PrivateKeyDer<'static>) -> Result<Arc<dyn SigningKey>, rustls::Error> {
        Err(rustls::Error::General("no client certificates".into()))
    }
}

static X25519_KX: X25519 = X25519;
static P256_KX: P256 = P256;

pub fn provider() -> CryptoProvider {
    CryptoProvider {
        cipher_suites: alloc::vec![
            SupportedCipherSuite::Tls13(&TLS13_AES_128_GCM_SHA256),
            SupportedCipherSuite::Tls13(&TLS13_CHACHA20_POLY1305_SHA256),
            SupportedCipherSuite::Tls13(&TLS13_AES_256_GCM_SHA384),
        ],
        kx_groups: alloc::vec![&X25519_KX, &P256_KX],
        signature_verification_algorithms: ALGORITHMS,
        secure_random: &Random,
        key_provider: &NoKeys,
    }
}
