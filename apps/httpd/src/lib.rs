//! A tiny HTTP server on port 80 that shows the system status.
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write;

use rustros_util::conn::Conn;
use rustros_util::wire::{IpFmt, MacFmt};
use rustros_api::{Module, Sys, TcpListener, say};

const PORT: u16 = 80;
const MAX_REQUEST: usize = 8192;

#[derive(Default)]
pub struct Httpd {
    listener: Option<TcpListener>,
    conns: Vec<Conn>,
}

impl Httpd {
    pub fn new() -> Httpd {
        Httpd::default()
    }
}

fn escape(s: &str) -> String {
    s.chars().fold(String::new(), |mut o, c| {
        match c {
            '<' => o.push_str("&lt;"),
            '>' => o.push_str("&gt;"),
            '&' => o.push_str("&amp;"),
            c => o.push(c),
        }
        o
    })
}

fn status_page(sys: &mut dyn Sys) -> String {
    let Some(net) = sys.net() else { return String::new() };
    let n = net.net_info();
    let conns = net.tcp_connections();
    let mut b = String::new();
    let _ = write!(
        b,
        "<!doctype html><html><head><meta charset=utf-8><title>RustROS</title></head><body><pre>\
         RustROS is running\n\nuptime   {}s\nmac      {}\nip       {}\ngateway  {}\nrx/tx    {} / {} frames\napps     {}\n",
        sys.now_ms() / 1000,
        MacFmt(n.mac),
        IpFmt(n.ip),
        IpFmt(n.gw),
        n.rx,
        n.tx,
        sys.modules().join(", ")
    );
    if let Some(u) = sys.update_info() {
        let _ = writeln!(b, "slot     {}{}", u.slot, if u.trial { " (trial)" } else { "" });
    }
    b.push_str("\nTCP connections:\n");
    for c in conns {
        let _ = writeln!(b, "  :{:<5} {:<21} {:<12} {}", c.local_port, escape(&alloc::format!("{}", c.remote)), c.state, c.owner.unwrap_or("-"));
    }
    b.push_str("</pre></body></html>\n");
    b
}

fn response(status: &str, body: &str) -> String {
    alloc::format!(
        "HTTP/1.0 {status}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

impl Module for Httpd {
    fn name(&self) -> &'static str {
        "httpd"
    }

    fn start(&mut self, sys: &mut dyn Sys) {
        let Some(net) = sys.net() else { return };
        match net.tcp_listen(PORT) {
            Ok(l) => self.listener = Some(l),
            Err(e) => say!(net, "httpd: cannot listen on {}: {:?}\n", PORT, e),
        }
    }

    fn poll(&mut self, sys: &mut dyn Sys) {
        if let (Some(l), Some(net)) = (self.listener, sys.net()) {
            while let Ok((s, peer)) = net.tcp_accept(l) {
                self.conns.push(Conn::new(s, peer));
            }
        }
        self.conns.retain_mut(|c| {
            let Some(net) = sys.net() else { return false };
            if !c.pump(net, MAX_REQUEST) {
                return false;
            }
            if c.queued() > 0 {
                return true; // response on its way
            }
            if c.inbuf.windows(4).any(|w| w == b"\r\n\r\n") {
                let page = status_page(sys);
                c.write(response("200 OK", &page).as_bytes());
                c.inbuf.clear();
                c.close();
                if let Some(net) = sys.net() {
                    c.pump(net, 0);
                }
            } else if c.inbuf.len() >= MAX_REQUEST || c.eof {
                c.write(response("400 Bad Request", "bad request\n").as_bytes());
                c.close();
                if let Some(net) = sys.net() {
                    c.pump(net, 0);
                }
            }
            true
        });
    }
}
