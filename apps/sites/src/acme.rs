//! ACME (RFC 8555) with HTTP-01: a certificate for a site's names from
//! Let's Encrypt (or any ACME CA). One order at a time, moved on by `poll`.
//! The challenges' key authorizations go into the store
//! (`acme/challenge/<token>`), where the sites app answers them on port 80.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use httpc::{Call, Request, Url};
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use rustros_api::Sys;
use rustros_util::json::{Json, quote};
use rustros_util::wire::Ip;

pub const LETS_ENCRYPT: &str = "https://acme-v02.api.letsencrypt.org/directory";
const CALL_MS: u64 = 30_000;
const POLL_MS: u64 = 2000;
/// Polls of an authorization or an order before giving up.
const POLLS: u32 = 60;

pub fn b64u(data: &[u8]) -> String {
    rustros_util::base64::encode(data).replace('+', "-").replace('/', "_").trim_end_matches('=').into()
}

// ------------------------------------------------------------ DER

fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut o = alloc::vec![tag];
    let n = content.len();
    if n < 0x80 {
        o.push(n as u8);
    } else if n < 0x100 {
        o.extend_from_slice(&[0x81, n as u8]);
    } else {
        o.extend_from_slice(&[0x82, (n >> 8) as u8, n as u8]);
    }
    o.extend_from_slice(content);
    o
}

fn seq(parts: &[&[u8]]) -> Vec<u8> {
    tlv(0x30, &parts.concat())
}

const OID_EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
const OID_P256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
const OID_ECDSA_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
const OID_EXTENSION_REQUEST: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x0e];
const OID_SUBJECT_ALT_NAME: &[u8] = &[0x55, 0x1d, 0x11];
const OID_COMMON_NAME: &[u8] = &[0x55, 0x04, 0x03];

/// A PKCS#10 request for `names` (the first is the subject's CN), signed by `key`.
pub fn csr(key: &SigningKey, names: &[String]) -> Vec<u8> {
    let point = key.verifying_key().to_encoded_point(false);
    let spki = seq(&[&seq(&[&tlv(0x06, OID_EC_PUBLIC_KEY), &tlv(0x06, OID_P256)]), &tlv(0x03, &[&[0u8][..], point.as_bytes()].concat())]);
    let subject = seq(&[&tlv(0x31, &seq(&[&tlv(0x06, OID_COMMON_NAME), &tlv(0x0c, names[0].as_bytes())]))]);
    let sans: Vec<u8> = names.iter().flat_map(|n| tlv(0x82, n.as_bytes())).collect();
    let ext = seq(&[&seq(&[&tlv(0x06, OID_SUBJECT_ALT_NAME), &tlv(0x04, &tlv(0x30, &sans))])]);
    let attrs = tlv(0xa0, &seq(&[&tlv(0x06, OID_EXTENSION_REQUEST), &tlv(0x31, &ext)]));
    let info = seq(&[&tlv(0x02, &[0]), &subject, &spki, &attrs]);
    let sig: Signature = key.sign(&info);
    seq(&[&info, &seq(&[&tlv(0x06, OID_ECDSA_SHA256)]), &tlv(0x03, &[&[0u8][..], sig.to_der().as_bytes()].concat())])
}

/// A P-256 key as PKCS#8 PEM (for the TLS server).
pub fn key_pem(key: &SigningKey) -> String {
    let mut der = alloc::vec![
        0x30, 0x41, 0x02, 0x01, 0x00, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x04, 0x27, 0x30, 0x25, 0x02,
        0x01, 0x01, 0x04, 0x20
    ];
    der.extend_from_slice(&key.to_bytes());
    let b = rustros_util::base64::encode(&der);
    let mut s = String::from("-----BEGIN PRIVATE KEY-----\n");
    for line in b.as_bytes().chunks(64) {
        s += core::str::from_utf8(line).unwrap_or("");
        s.push('\n');
    }
    s + "-----END PRIVATE KEY-----\n"
}

/// A fresh P-256 key from the TLS crate's generator.
pub fn new_key() -> Option<SigningKey> {
    for _ in 0..8 {
        let mut b = [0u8; 32];
        if !tls::random(&mut b) {
            return None;
        }
        if let Ok(k) = SigningKey::from_slice(&b) {
            return Some(k);
        }
    }
    None
}

// ------------------------------------------------------------ the order

#[derive(Clone, Copy, PartialEq, Debug)]
enum Step {
    Directory,
    Nonce,
    Account,
    Order,
    Authz,
    Respond,
    PollAuthz,
    Finalize,
    PollOrder,
    Download,
}

pub struct Order {
    pub site: String,
    names: Vec<String>,
    directory: String,
    ca: String,
    dns: Ip,
    email: String,
    account: SigningKey,
    kid: Option<String>,
    nonce: Option<String>,
    new_nonce: String,
    new_account: String,
    new_order: String,
    order_url: String,
    authzs: Vec<String>,
    ai: usize,
    challenge: String,
    finalize: String,
    cert_url: String,
    cert_key: SigningKey,
    step: Step,
    call: Option<Call>,
    wait_until: u64,
    polls: u32,
    /// the challenge tokens put in the store (removed at the end)
    pub tokens: Vec<String>,
}

/// How an order ended: (certificate chain PEM, its key PEM), or why not.
pub type Outcome = Result<(String, String), String>;

impl Order {
    #[allow(clippy::too_many_arguments)]
    pub fn new(site: &str, names: Vec<String>, directory: &str, ca: &str, dns: Ip, email: &str, account: SigningKey, kid: Option<String>) -> Option<Order> {
        Some(Order {
            site: String::from(site),
            names,
            directory: String::from(directory),
            ca: String::from(ca),
            dns,
            email: String::from(email),
            account,
            kid,
            nonce: None,
            new_nonce: String::new(),
            new_account: String::new(),
            new_order: String::new(),
            order_url: String::new(),
            authzs: Vec::new(),
            ai: 0,
            challenge: String::new(),
            finalize: String::new(),
            cert_url: String::new(),
            cert_key: new_key()?,
            step: Step::Directory,
            call: None,
            wait_until: 0,
            polls: 0,
            tokens: Vec::new(),
        })
    }

    /// The account URL (kid) once known, to keep.
    pub fn kid(&self) -> Option<&str> {
        self.kid.as_deref()
    }

    fn jwk(&self) -> String {
        let p = self.account.verifying_key().to_encoded_point(false);
        let b = p.as_bytes();
        format!("{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{}\",\"y\":\"{}\"}}", b64u(&b[1..33]), b64u(&b[33..65]))
    }

    pub fn thumbprint(&self) -> String {
        b64u(&rustros_util::sha256::Sha256::digest(self.jwk().as_bytes()))
    }

    /// A JWS of `payload` (None: POST-as-GET) for `url`.
    fn jws(&self, url: &str, payload: Option<&str>) -> String {
        let who = match &self.kid {
            Some(k) => format!("\"kid\":{}", quote(k)),
            None => format!("\"jwk\":{}", self.jwk()),
        };
        let protected = format!("{{\"alg\":\"ES256\",{who},\"nonce\":{},\"url\":{}}}", quote(self.nonce.as_deref().unwrap_or("")), quote(url));
        let p = b64u(protected.as_bytes());
        let pl = payload.map(|x| b64u(x.as_bytes())).unwrap_or_default();
        let sig: Signature = self.account.sign(format!("{p}.{pl}").as_bytes());
        format!("{{\"protected\":\"{p}\",\"payload\":\"{pl}\",\"signature\":\"{}\"}}", b64u(&sig.to_bytes()))
    }

    fn start(&mut self, sys: &mut dyn Sys, method: &'static str, url: &str, body: Option<String>, now: u64) -> Result<(), String> {
        let (to, path) = Url::parse_full(url).ok_or_else(|| format!("not an https URL: {url}"))?;
        let net = sys.net().ok_or("no network")?;
        let req = Request {
            method,
            content_type: if body.is_some() { "application/jose+json" } else { "" },
            path,
            bearer: None,
            body: body.map(String::into_bytes).unwrap_or_default(),
            deadline: now + CALL_MS,
        };
        self.call = Some(Call::start(net, &to, &self.ca, &format!("rustros-sites/{}", rustros_api::BUILD), self.dns, req));
        Ok(())
    }

    fn post(&mut self, sys: &mut dyn Sys, url: &str, payload: Option<&str>, now: u64) -> Result<(), String> {
        let body = self.jws(url, payload);
        self.start(sys, "POST", url, Some(body), now)
    }

    /// The request of the current step.
    fn begin(&mut self, sys: &mut dyn Sys, now: u64) -> Result<(), String> {
        match self.step {
            Step::Directory => self.start(sys, "GET", &self.directory.clone(), None, now),
            Step::Nonce => self.start(sys, "GET", &self.new_nonce.clone(), None, now),
            Step::Account => {
                let contact = if self.email.is_empty() { String::new() } else { format!(",\"contact\":[{}]", quote(&format!("mailto:{}", self.email))) };
                let p = format!("{{\"termsOfServiceAgreed\":true{contact}}}");
                self.post(sys, &self.new_account.clone(), Some(&p), now)
            }
            Step::Order => {
                let ids: Vec<String> = self.names.iter().map(|n| format!("{{\"type\":\"dns\",\"value\":{}}}", quote(n))).collect();
                let p = format!("{{\"identifiers\":[{}]}}", ids.join(","));
                self.post(sys, &self.new_order.clone(), Some(&p), now)
            }
            Step::Authz | Step::PollAuthz => self.post(sys, &self.authzs[self.ai].clone(), None, now),
            Step::Respond => self.post(sys, &self.challenge.clone(), Some("{}"), now),
            Step::Finalize => {
                let p = format!("{{\"csr\":\"{}\"}}", b64u(&csr(&self.cert_key, &self.names)));
                self.post(sys, &self.finalize.clone(), Some(&p), now)
            }
            Step::PollOrder => self.post(sys, &self.order_url.clone(), None, now),
            Step::Download => self.post(sys, &self.cert_url.clone(), None, now),
        }
    }

    /// None while it goes on.
    pub fn poll(&mut self, sys: &mut dyn Sys, now: u64) -> Option<Outcome> {
        if now < self.wait_until {
            return None;
        }
        let Some(mut call) = self.call.take() else {
            if let Err(e) = self.begin(sys, now) {
                return Some(Err(e));
            }
            return None;
        };
        let net = sys.net()?;
        let done = match call.poll(net, now) {
            None => {
                self.call = Some(call);
                return None;
            }
            Some(d) => d,
        };
        if let Some(n) = call.header("Replay-Nonce") {
            self.nonce = Some(String::from(n));
        }
        let (status, body) = match done {
            Ok(x) => x,
            Err(e) => return Some(Err(format!("{:?}: {e}", self.step))),
        };
        let j = Json::parse(&body);
        let field = |k: &str| j.as_ref().and_then(|j| j.get(k)).and_then(Json::str).map(String::from);
        if status >= 400 {
            let kind = field("type").unwrap_or_default();
            if kind.ends_with(":badNonce") && self.nonce.is_some() {
                return None; // again, with the new nonce
            }
            return Some(Err(format!("{:?}: {status} {} {}", self.step, kind, field("detail").unwrap_or_default())));
        }
        match self.step {
            Step::Directory => {
                let (Some(n), Some(a), Some(o)) = (field("newNonce"), field("newAccount"), field("newOrder")) else {
                    return Some(Err(String::from("the directory lacks newNonce/newAccount/newOrder")));
                };
                (self.new_nonce, self.new_account, self.new_order) = (n, a, o);
                self.step = Step::Nonce;
            }
            Step::Nonce => self.step = if self.kid.is_some() { Step::Order } else { Step::Account },
            Step::Account => {
                self.kid = call.header("Location").map(String::from);
                if self.kid.is_none() {
                    return Some(Err(String::from("no account URL")));
                }
                self.step = Step::Order;
            }
            Step::Order => {
                self.order_url = call.header("Location").map(String::from).unwrap_or_default();
                self.finalize = field("finalize").unwrap_or_default();
                self.authzs = j.as_ref().and_then(|j| j.get("authorizations")).map(|a| (0..).map_while(|i| a.at(i)).filter_map(Json::str).map(String::from).collect()).unwrap_or_default();
                if self.authzs.is_empty() || self.finalize.is_empty() {
                    return Some(Err(String::from("the order lacks authorizations or finalize")));
                }
                self.ai = 0;
                self.step = Step::Authz;
            }
            Step::Authz => {
                if field("status").as_deref() == Some("valid") {
                    return self.next_authz();
                }
                let chs = j.as_ref().and_then(|j| j.get("challenges"));
                let http = chs.and_then(|c| (0..).map_while(|i| c.at(i)).find(|c| c.get("type").and_then(Json::str) == Some("http-01")));
                let (Some(url), Some(token)) = (http.and_then(|c| c.get("url")).and_then(Json::str), http.and_then(|c| c.get("token")).and_then(Json::str)) else {
                    return Some(Err(String::from("no http-01 challenge offered")));
                };
                let keyauth = format!("{token}.{}", self.thumbprint());
                if sys.kv().is_none_or(|kv| kv.put(&format!("acme/challenge/{token}"), keyauth.as_bytes()).is_err()) {
                    return Some(Err(String::from("cannot store the challenge")));
                }
                self.tokens.push(String::from(token));
                self.challenge = String::from(url);
                self.step = Step::Respond;
            }
            Step::Respond => {
                self.polls = 0;
                self.step = Step::PollAuthz;
                self.wait_until = now + POLL_MS;
            }
            Step::PollAuthz => match field("status").as_deref() {
                Some("valid") => return self.next_authz(),
                Some("pending") | Some("processing") if self.polls < POLLS => {
                    self.polls += 1;
                    self.wait_until = now + POLL_MS;
                }
                s => {
                    let why = j
                        .as_ref()
                        .and_then(|j| j.get("challenges"))
                        .and_then(|c| (0..).map_while(|i| c.at(i)).find_map(|c| c.path(&["error", "detail"]).and_then(Json::str).map(String::from)))
                        .unwrap_or_default();
                    return Some(Err(format!("{} not validated ({}): {why}", self.names[self.ai.min(self.names.len() - 1)], s.unwrap_or("?"))));
                }
            },
            Step::Finalize | Step::PollOrder => match field("status").as_deref() {
                Some("valid") => {
                    self.cert_url = field("certificate").unwrap_or_default();
                    if self.cert_url.is_empty() {
                        return Some(Err(String::from("valid order without a certificate URL")));
                    }
                    self.step = Step::Download;
                }
                Some("processing") | Some("pending") | Some("ready") if self.polls < POLLS => {
                    self.polls += 1;
                    self.step = Step::PollOrder;
                    self.wait_until = now + POLL_MS;
                }
                s => return Some(Err(format!("the order is {}", s.unwrap_or("?")))),
            },
            Step::Download => {
                let pem = String::from_utf8_lossy(&body).into_owned();
                if !pem.contains("-----BEGIN CERTIFICATE-----") {
                    return Some(Err(String::from("the certificate download is not PEM")));
                }
                return Some(Ok((pem, key_pem(&self.cert_key))));
            }
        }
        None
    }

    fn next_authz(&mut self) -> Option<Outcome> {
        self.ai += 1;
        if self.ai < self.authzs.len() {
            self.step = Step::Authz;
        } else {
            self.polls = 0;
            self.step = Step::Finalize;
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csr_for_openssl() {
        let key = SigningKey::from_slice(&[7u8; 32]).unwrap();
        let der = csr(&key, &[String::from("rustros.com"), String::from("www.rustros.com")]);
        if let Ok(p) = std::env::var("CSR_OUT") {
            std::fs::write(p, &der).unwrap();
            std::fs::write(std::env::var("KEY_OUT").unwrap(), key_pem(&key)).unwrap();
        }
        assert_eq!(der[0], 0x30);
        assert_eq!(b64u(&[0xfb, 0xff]), "-_8");
    }
}
