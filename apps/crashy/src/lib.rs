//! Test module for isolation and fallback: a line-based TCP service on port
//! 7001. The same code builds as a WebAssembly module and as a native one.
//!
//!   hello        -> greeting with uptime and start count
//!   set <k> <v>  -> store in the key-value store
//!   get <k>      -> read it back
//!   panic        -> panic (the instance traps and is restarted)
//!   loop         -> spin forever (stopped by the fuel limit)
//!   oom          -> allocate until the memory cap is hit
//!   bad          -> pass a bogus pointer to the host (must not hurt the host)

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use rustros_util::conn::Conn;
use rustros_api::socket::Socket;
use rustros_api::{Caps, Frame, Module, Sys, say};

const PORT: u16 = 7001;

#[derive(Default)]
pub struct Crashy {
    listener: Option<Socket>,
    conns: Vec<Conn>,
    starts: u64,
    probe: Option<fn() -> i32>,
}

impl Crashy {
    fn command(&mut self, sys: &mut dyn Sys, line: &str) -> String {
        let mut w = line.split_whitespace();
        match (w.next(), w.next(), w.next()) {
            (Some("hello"), _, _) => format!("hi from crashy, up {} ms, start #{}\n", sys.now_ms(), self.starts),
            (Some("set"), Some(k), Some(v)) => format!("{:?}\n", sys.kv().map(|kv| kv.put(k, v.as_bytes()))),
            (Some("get"), Some(k), _) => match sys.kv().and_then(|kv| kv.get(k)) {
                Some(v) => format!("{}\n", String::from_utf8_lossy(&v)),
                None => "(none)\n".into(),
            },
            (Some("panic"), _, _) => panic!("crashy was asked to panic"),
            (Some("loop"), _, _) => {
                #[allow(clippy::empty_loop)]
                loop {}
            }
            (Some("oom"), _, _) => {
                let mut v: Vec<Vec<u8>> = Vec::new();
                loop {
                    v.push(vec![1u8; 1 << 20]);
                }
            }
            (Some("bad"), _, _) => match self.probe {
                Some(probe) => format!("host said {}\n", probe()),
                None => "no probe in this build\n".into(),
            },
            _ => "?\n".into(),
        }
    }
}

impl Crashy {
    pub fn new() -> Crashy {
        Crashy::default()
    }

    /// `probe` makes a host call with bogus pointers and returns its result
    /// (the WebAssembly build has one; natively there is nothing to test).
    pub fn with_bad_pointer_probe(probe: fn() -> i32) -> Crashy {
        Crashy { probe: Some(probe), ..Crashy::default() }
    }
}

impl Module for Crashy {
    fn name(&self) -> &'static str {
        "crashy"
    }

    // a packet app that wants plain packets (tests the system's offload
    // fallback); it only looks
    fn caps(&self) -> Caps {
        Caps::NET | Caps::KV | Caps::PACKET
    }

    fn on_frames(&mut self, _sys: &mut dyn Sys, frames: &mut [Frame]) {
        assert!(frames.iter().all(|f| f.offload.is_none()), "offloads reached an app that did not ask for them");
    }

    fn start(&mut self, sys: &mut dyn Sys) {
        let Some(kv) = sys.kv() else { return };
        let n = kv.get("starts").map_or(0, |v| String::from_utf8_lossy(&v).parse().unwrap_or(0)) + 1;
        let _ = kv.put("starts", n.to_string().as_bytes());
        self.starts = n;
        self.listener = sys.net().and_then(|net| rustros_util::sock::tcp_listen(net, PORT).ok());
        say!(sys, "crashy: listening on {} (start #{})\n", PORT, n);
    }

    fn poll(&mut self, sys: &mut dyn Sys) {
        if let Some(l) = self.listener {
            while let Some(Ok((s, peer))) = sys.net().map(|n| n.accept(l, 0)) {
                self.conns.push(Conn::new(s, peer));
            }
        }
        let mut conns = core::mem::take(&mut self.conns);
        conns.retain_mut(|c| {
            if !c.pump(sys.net().unwrap(), 4096) {
                return false;
            }
            while let Some(i) = c.inbuf.iter().position(|&b| b == b'\n') {
                let line: Vec<u8> = c.inbuf.drain(..=i).collect();
                let reply = self.command(sys, String::from_utf8_lossy(&line).trim());
                c.write(reply.as_bytes());
            }
            if c.eof {
                let _ = c.close();
            }
            c.pump(sys.net().unwrap(), 4096)
        });
        self.conns = conns;
    }
}

