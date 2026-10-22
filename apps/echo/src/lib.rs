//! Echo service on TCP and UDP port 7.
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::vec::Vec;

use rustros_util::conn::Conn;
use rustros_api::{Module, Sys, TcpListener, UdpSocket, say};

const PORT: u16 = 7;
const LIMIT: usize = 64 * 1024;

#[derive(Default)]
pub struct Echo {
    tcp: Option<TcpListener>,
    udp: Option<UdpSocket>,
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
        match (net.tcp_listen(PORT), net.udp_bind(PORT)) {
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
            while let Ok((n, from)) = net.udp_recv_from(u, &mut buf) {
                let _ = net.udp_send_to(u, from, &buf[..n]);
            }
        }
        if let Some(l) = self.tcp {
            while let Ok((s, peer)) = net.tcp_accept(l) {
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
                c.close();
            }
            true
        });
    }
}
