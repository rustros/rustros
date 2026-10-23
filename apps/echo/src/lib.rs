//! Echo service on TCP and UDP port 7.
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::vec::Vec;

use rustros_util::conn::Conn;
use rustros_api::socket::Socket;
use rustros_api::{Module, Sys, say};

const PORT: u16 = 7;
const LIMIT: usize = 64 * 1024;

#[derive(Default)]
pub struct Echo {
    tcp: Option<Socket>,
    udp: Option<Socket>,
    conns: Vec<Conn>,
}

impl Echo {
    pub fn new() -> Echo {
        Echo::default()
    }
}

impl Module for Echo {
    fn name(&self) -> &'static str {
        "echo"
    }

    fn start(&mut self, sys: &mut dyn Sys) {
        let Some(net) = sys.net() else { return };
        match (rustros_util::sock::tcp_listen(net, PORT), rustros_util::sock::udp_bind(net, PORT)) {
            (Ok(t), Ok(u)) => {
                self.tcp = Some(t);
                self.udp = Some(u);
            }
            (t, u) => say!(net, "echo: cannot open port {}: {:?} {:?}\n", PORT, t.err(), u.err()),
        }
    }

    fn poll(&mut self, sys: &mut dyn Sys) {
        let Some(net) = sys.net() else { return };
        if let Some(u) = self.udp {
            let mut buf = [0u8; 1500];
            while let Ok((n, from)) = net.recvfrom(u, &mut buf, 0) {
                let _ = net.sendto(u, &buf[..n], 0, from.as_ref());
            }
        }
        if let Some(l) = self.tcp {
            while let Ok((s, peer)) = net.accept(l, 0) {
                self.conns.push(Conn::new(s, peer));
            }
        }
        self.conns.retain_mut(|c| {
            if !c.pump(net, LIMIT) {
                return false;
            }
            if !c.inbuf.is_empty() && c.queued() < LIMIT {
                let data = core::mem::take(&mut c.inbuf);
                c.write(&data);
                c.pump(net, LIMIT);
            }
            if c.eof && c.inbuf.is_empty() {
                let _ = c.close();
            }
            true
        });
    }
}
