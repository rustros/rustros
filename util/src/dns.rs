//! A minimal DNS client: one A query, the first address in the answer
//! (CNAME chains come back in the same answer).

use alloc::vec::Vec;

use crate::wire::Ip;

/// A recursive query for the A record of `name` (None if it is no name).
pub fn query(id: u16, name: &str) -> Option<Vec<u8>> {
    let name = name.trim_end_matches('.');
    if name.is_empty() || name.len() > 253 {
        return None;
    }
    let mut q = Vec::with_capacity(18 + name.len());
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]); // RD, one question
    for label in name.split('.') {
        if label.is_empty() || label.len() > 63 {
            return None;
        }
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.extend_from_slice(&[0, 0, 1, 0, 1]); // root, type A, class IN
    Some(q)
}

fn skip_name(p: &[u8], mut o: usize) -> Option<usize> {
    loop {
        let l = *p.get(o)? as usize;
        match l {
            0 => return Some(o + 1),
            l if l & 0xC0 == 0xC0 => return Some(o + 2),
            l => o += 1 + l,
        }
    }
}

/// The answer to query `id`: Ok(first A address), Err(()) if the name does
/// not resolve (an error code or no A record); None if this is not it.
pub fn answer(p: &[u8], id: u16) -> Option<Result<Ip, ()>> {
    if p.len() < 12 || u16::from_be_bytes([p[0], p[1]]) != id || p[2] & 0x80 == 0 {
        return None;
    }
    if p[3] & 0x0F != 0 {
        return Some(Err(()));
    }
    let (qd, an) = (u16::from_be_bytes([p[4], p[5]]), u16::from_be_bytes([p[6], p[7]]));
    let mut o = 12;
    for _ in 0..qd {
        o = skip_name(p, o)? + 4;
    }
    for _ in 0..an {
        o = skip_name(p, o)?;
        let h = p.get(o..o + 10)?;
        let (ty, len) = (u16::from_be_bytes([h[0], h[1]]), u16::from_be_bytes([h[8], h[9]]) as usize);
        o += 10;
        if ty == 1 && len == 4 {
            let a = p.get(o..o + 4)?;
            return Some(Ok(u32::from_be_bytes([a[0], a[1], a[2], a[3]])));
        }
        o += len;
    }
    Some(Err(()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let q = query(0x1234, "ip.fm").unwrap();
        assert_eq!(&q[12..], b"\x02ip\x02fm\x00\x00\x01\x00\x01");
        // a reply with a CNAME, then the A record (names compressed)
        let mut r = q.clone();
        r[2] = 0x81;
        r[3] = 0x80;
        r[7] = 2;
        r.extend_from_slice(&[0xC0, 12, 0, 5, 0, 1, 0, 0, 0, 60, 0, 2, 0xC0, 12]);
        r.extend_from_slice(&[0xC0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 203, 0, 113, 7]);
        assert_eq!(answer(&r, 0x1234), Some(Ok(0xCB00_7107)));
        assert_eq!(answer(&r, 0x9999), None, "another query's answer");
        r[3] = 0x83; // NXDOMAIN
        assert_eq!(answer(&r, 0x1234), Some(Err(())));
        assert_eq!(answer(&r[..20], 0x1234), Some(Err(())));
        assert!(query(1, "").is_none() && query(1, "a..b").is_none());
    }
}

/// One name being looked up, polled: `Lookup::start`, then `poll` until it
/// says how it ended.
pub struct Lookup {
    sock: rustros_api::UdpSocket,
    id: u16,
    server: Ip,
    name: alloc::string::String,
    sent: u64,
    tries: u8,
}

/// How a lookup ended.
pub enum Looked {
    Found(Ip),
    /// The name does not resolve (or is no name).
    NoSuchName,
    /// The server did not answer.
    NoAnswer,
}

impl Lookup {
    const RETRY_MS: u64 = 2000;
    const TRIES: u8 = 3;

    pub fn start(net: &mut dyn rustros_api::Net, name: &str, server: Ip) -> Option<Lookup> {
        let sock = net.udp_bind(0).ok()?;
        Some(Lookup { sock, id: net.random() as u16, server, name: alloc::string::String::from(name), sent: 0, tries: 0 })
    }

    /// None while waiting; the socket is closed once it has ended.
    pub fn poll(&mut self, net: &mut dyn rustros_api::Net, now: u64) -> Option<Looked> {
        let mut buf = [0u8; 1500];
        while let Ok((n, from)) = net.udp_recv_from(self.sock, &mut buf) {
            if from.ip != self.server {
                continue;
            }
            match answer(&buf[..n], self.id) {
                Some(Ok(ip)) => return Some(self.end(net, Looked::Found(ip))),
                Some(Err(())) => return Some(self.end(net, Looked::NoSuchName)),
                None => {}
            }
        }
        if self.sent == 0 || now - self.sent >= Self::RETRY_MS {
            if self.tries >= Self::TRIES {
                return Some(self.end(net, Looked::NoAnswer));
            }
            self.tries += 1;
            self.sent = now.max(1);
            let Some(q) = query(self.id, &self.name) else { return Some(self.end(net, Looked::NoSuchName)) };
            let _ = net.udp_send_to(self.sock, rustros_api::SocketAddr { ip: self.server, port: 53 }, &q);
        }
        None
    }

    /// Give up (the socket is closed).
    pub fn cancel(self, net: &mut dyn rustros_api::Net) {
        net.udp_close(self.sock);
    }

    fn end(&mut self, net: &mut dyn rustros_api::Net, r: Looked) -> Looked {
        net.udp_close(self.sock);
        r
    }
}
