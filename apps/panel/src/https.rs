//! One HTTPS request at a time, moved on by `poll` (the main loop never
//! waits): the name looked up, TCP, TLS, the request, the answer (its body
//! by Content-Length, chunked, or up to the end).

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use rustros_api::{Net, SocketAddr};
use rustros_util::conn::Conn;
use rustros_util::dns::{Looked, Lookup};
use rustros_util::wire::{Ip, parse_ip};

/// The most of an answer kept (files for module-install are up to 1 MiB).
const MAX_ANSWER: usize = 2 << 20;

/// Where the panel is: "https://host[:port]" (a path after it is ignored).
#[derive(Clone, Debug, PartialEq)]
pub struct Url {
    pub host: String,
    pub port: u16,
}

impl Url {
    pub fn parse(s: &str) -> Option<Url> {
        let rest = s.trim().strip_prefix("https://")?;
        let hostport = rest.split('/').next()?;
        let (host, port) = match hostport.rsplit_once(':') {
            Some((h, p)) => (h, p.parse().ok()?),
            None => (hostport, 443),
        };
        (!host.is_empty()).then(|| Url { host: String::from(host), port })
    }
}

pub struct Request {
    pub method: &'static str,
    pub path: String,
    /// "Authorization: Bearer ..." value, if any
    pub bearer: Option<String>,
    pub body: Vec<u8>,
    /// give up by then (ms since boot)
    pub deadline: u64,
}

enum Phase {
    Resolve(Lookup),
    Connecting(Conn),
    Talking(Conn, tls::Tls),
}

/// A request on its way.
pub struct Call {
    url: Url,
    ca: String,
    agent: String,
    req: Request,
    phase: Option<Phase>,
    answer: Vec<u8>,
}

/// How a call ended: (status, body), or why it failed.
pub type Done = Result<(u16, Vec<u8>), String>;

impl Call {
    pub fn start(net: &mut dyn Net, url: &Url, ca: &str, agent: &str, dns: Ip, req: Request) -> Call {
        let mut c = Call { url: url.clone(), ca: String::from(ca), agent: String::from(agent), req, phase: None, answer: Vec::new() };
        c.phase = match parse_ip(&c.url.host) {
            Some(ip) => c.connect(net, ip).ok(),
            None => Lookup::start(net, &c.url.host, dns).map(Phase::Resolve),
        };
        c
    }

    fn connect(&self, net: &mut dyn Net, ip: Ip) -> Result<Phase, String> {
        let to = SocketAddr { ip, port: self.url.port };
        let s = net.tcp_connect(to).map_err(|e| format!("connect {to}: {e:?}"))?;
        Ok(Phase::Connecting(Conn::new(s, to)))
    }

    fn request_bytes(&self) -> Vec<u8> {
        let host = if self.url.port == 443 { self.url.host.clone() } else { format!("{}:{}", self.url.host, self.url.port) };
        let auth = self.req.bearer.as_ref().map(|b| format!("Authorization: Bearer {b}\r\n")).unwrap_or_default();
        let mut r = format!(
            "{} {} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {}\r\n{auth}Accept: application/json\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            self.req.method,
            self.req.path,
            self.agent,
            self.req.body.len()
        )
        .into_bytes();
        r.extend_from_slice(&self.req.body);
        r
    }

    /// Give it up (sockets closed).
    pub fn abort(mut self, net: &mut dyn Net) {
        match self.phase.take() {
            Some(Phase::Resolve(l)) => l.cancel(net),
            Some(Phase::Connecting(mut c)) | Some(Phase::Talking(mut c, _)) => c.abort(net),
            None => {}
        }
    }

    /// None while it goes on.
    pub fn poll(&mut self, net: &mut dyn Net, now: u64) -> Option<Done> {
        if now >= self.req.deadline {
            let what = match &self.phase {
                Some(Phase::Resolve(_)) => "looking up the panel",
                Some(Phase::Connecting(_)) => "connecting",
                Some(Phase::Talking(_, t)) if !t.established => "TLS",
                _ => "the answer",
            };
            return Some(self.fail(net, format!("timed out ({what})")));
        }
        let Some(phase) = self.phase.take() else { return Some(Err(format!("cannot reach {}", self.url.host))) };
        match phase {
            Phase::Resolve(mut l) => match l.poll(net, now) {
                None => self.phase = Some(Phase::Resolve(l)),
                Some(Looked::Found(ip)) => match self.connect(net, ip) {
                    Ok(p) => self.phase = Some(p),
                    Err(e) => return Some(Err(e)),
                },
                Some(_) => return Some(Err(format!("{} does not resolve", self.url.host))),
            },
            Phase::Connecting(mut c) => match net.tcp_is_connected(c.stream) {
                Ok(false) => self.phase = Some(Phase::Connecting(c)),
                Ok(true) => {
                    let mut t = match tls::Tls::client_trusting(&self.url.host, &self.ca) {
                        Ok(t) => t,
                        Err(e) => {
                            c.abort(net);
                            return Some(Err(format!("TLS: {e}")));
                        }
                    };
                    t.write(&self.request_bytes()); // sent once the handshake is done
                    let out = t.take_outgoing();
                    c.write(&out);
                    self.phase = Some(Phase::Talking(c, t));
                }
                Err(_) => return Some(Err(format!("{}:{} refused or unreachable", self.url.host, self.url.port))),
            },
            Phase::Talking(mut c, mut t) => {
                let alive = c.pump(net, 64 * 1024);
                if !c.inbuf.is_empty() {
                    let cipher = core::mem::take(&mut c.inbuf);
                    t.feed(&cipher);
                }
                if let Some(e) = t.error.take() {
                    c.abort(net);
                    return Some(Err(format!("TLS: {e}")));
                }
                let out = t.take_outgoing();
                if !out.is_empty() {
                    c.write(&out);
                    c.pump(net, 0);
                }
                self.answer.extend_from_slice(&t.take_received());
                if self.answer.len() > MAX_ANSWER {
                    c.abort(net);
                    return Some(Err(String::from("answer too big")));
                }
                if let Some(done) = parse(&self.answer, false) {
                    c.close();
                    c.pump(net, 0);
                    return Some(done);
                }
                if !alive || c.eof || t.closed {
                    let end = parse(&self.answer, true);
                    c.abort(net);
                    return Some(end.unwrap_or_else(|| Err(String::from("the connection ended without an answer"))));
                }
                self.phase = Some(Phase::Talking(c, t));
            }
        }
        None
    }

    fn fail(&mut self, net: &mut dyn Net, why: String) -> Done {
        match self.phase.take() {
            Some(Phase::Resolve(l)) => l.cancel(net),
            Some(Phase::Connecting(mut c)) | Some(Phase::Talking(mut c, _)) => c.abort(net),
            None => {}
        }
        Err(why)
    }
}

/// A whole answer in `b`: (status, body); None while more is to come
/// (`ended`: nothing more comes, a body without a length ends here).
pub fn parse(b: &[u8], ended: bool) -> Option<Done> {
    let end = b.windows(4).position(|w| w == b"\r\n\r\n")?;
    let head = core::str::from_utf8(&b[..end]).ok()?;
    let mut lines = head.split("\r\n");
    let status: u16 = lines.next()?.split(' ').nth(1)?.parse().ok()?;
    let mut length = None;
    let mut chunked = false;
    for l in lines {
        if let Some((k, v)) = l.split_once(':') {
            let (k, v) = (k.trim(), v.trim());
            if k.eq_ignore_ascii_case("content-length") {
                length = v.parse::<usize>().ok();
            } else if k.eq_ignore_ascii_case("transfer-encoding") && v.to_ascii_lowercase().contains("chunked") {
                chunked = true;
            }
        }
    }
    let body = &b[end + 4..];
    if status == 204 || status == 304 || (100..200).contains(&status) {
        return Some(Ok((status, Vec::new())));
    }
    if chunked {
        return match dechunk(body) {
            Some(d) => Some(Ok((status, d))),
            None if ended => Some(Err(String::from("the answer was cut short"))),
            None => None,
        };
    }
    match length {
        Some(n) if body.len() >= n => Some(Ok((status, body[..n].to_vec()))),
        Some(_) if ended => Some(Err(String::from("the answer was cut short"))),
        Some(_) => None,
        None if ended => Some(Ok((status, body.to_vec()))),
        None => None,
    }
}

/// A complete chunked body, decoded; None while its last chunk is to come.
fn dechunk(mut b: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let eol = b.windows(2).position(|w| w == b"\r\n")?;
        let size = usize::from_str_radix(core::str::from_utf8(&b[..eol]).ok()?.split(';').next()?.trim(), 16).ok()?;
        b = &b[eol + 2..];
        if size == 0 {
            return Some(out);
        }
        if b.len() < size + 2 {
            return None;
        }
        out.extend_from_slice(&b[..size]);
        b = &b[size + 2..];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn answers() {
        assert_eq!(parse(b"HTTP/1.1 204 No Content\r\n\r\n", false), Some(Ok((204, Vec::new()))));
        assert_eq!(parse(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhel", false), None);
        assert_eq!(parse(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello", false), Some(Ok((200, b"hello".to_vec()))));
        let ch = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n";
        assert_eq!(parse(ch, false), Some(Ok((200, b"abcde".to_vec()))));
        assert_eq!(parse(&ch[..ch.len() - 7], false), None);
        assert_eq!(parse(b"HTTP/1.1 200 OK\r\n\r\nto the end", true), Some(Ok((200, b"to the end".to_vec()))));
        assert_eq!(Url::parse("https://panel.example.com:8443/x"), Some(Url { host: String::from("panel.example.com"), port: 8443 }));
        assert_eq!(Url::parse("https://p.example"), Some(Url { host: String::from("p.example"), port: 443 }));
        assert_eq!(Url::parse("http://p.example"), None);
    }
}
