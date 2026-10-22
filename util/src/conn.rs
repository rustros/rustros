//! Buffered TCP connection helper for applications.

use alloc::vec::Vec;

use rustros_api::{Net, NetError, SocketAddr, TcpStream};

/// A TCP stream with an input buffer and an output queue, so applications
/// do not have to deal with partial writes.
pub struct Conn {
    pub stream: TcpStream,
    pub peer: SocketAddr,
    /// Received data the application has not consumed yet.
    pub inbuf: Vec<u8>,
    /// The peer has closed its side.
    pub eof: bool,
    /// Total bytes received so far.
    pub received: u64,
    out: Vec<u8>,
    closing: bool,
    dead: bool,
}

impl Conn {
    pub fn new(stream: TcpStream, peer: SocketAddr) -> Conn {
        Conn { stream, peer, inbuf: Vec::new(), eof: false, received: 0, out: Vec::new(), closing: false, dead: false }
    }

    /// Flush queued output and read what is available, keeping at most
    /// `max_in` bytes in `inbuf`. Returns false once the connection is over.
    pub fn pump(&mut self, net: &mut dyn Net, max_in: usize) -> bool {
        if self.dead {
            return false;
        }
        while !self.out.is_empty() {
            match net.tcp_write(self.stream, &self.out) {
                Ok(n) => {
                    self.out.drain(..n);
                }
                Err(NetError::WouldBlock) => break,
                Err(_) => {
                    self.dead = true;
                    return false;
                }
            }
        }
        if self.closing {
            if self.out.is_empty() {
                net.tcp_close(self.stream);
                self.dead = true;
                return false;
            }
            return true;
        }
        let mut buf = [0u8; 2048];
        while self.inbuf.len() < max_in && !self.eof {
            let want = buf.len().min(max_in - self.inbuf.len());
            match net.tcp_read(self.stream, &mut buf[..want]) {
                Ok(0) => self.eof = true,
                Ok(n) => {
                    self.inbuf.extend_from_slice(&buf[..n]);
                    self.received += n as u64;
                }
                Err(NetError::WouldBlock) => break,
                Err(_) => {
                    self.dead = true;
                    return false;
                }
            }
        }
        true
    }

    /// Queue data for sending (sent by `pump`).
    pub fn write(&mut self, data: &[u8]) {
        self.out.extend_from_slice(data);
    }

    pub fn queued(&self) -> usize {
        self.out.len()
    }

    /// Close gracefully once the queued output has been sent.
    pub fn close(&mut self) {
        self.closing = true;
    }

    pub fn abort(&mut self, net: &mut dyn Net) {
        if !self.dead {
            net.tcp_abort(self.stream);
            self.dead = true;
        }
    }
}
