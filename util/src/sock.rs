//! Shorthands over the socket calls (`rustros_api::Net`, Linux semantics)
//! for what applications do most: listen on a port, connect out, bind a UDP
//! port, ask whether a connection is up yet.

use rustros_api::socket::*;
use rustros_api::{Ip, Net};

/// A listening TCP socket on `port` (0: an ephemeral one), any address.
pub fn tcp_listen(net: &mut dyn Net, port: u16) -> SockResult<Socket> {
    let s = net.socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0)?;
    let r = net.bind(s, &SockAddr::v4(0, port)).and_then(|()| net.listen(s, 64));
    on_error(net, s, r)
}

/// Connect to `to` from our address `from` (0: the one towards `to`). The
/// handshake goes on afterwards: `connected` says when it is done.
pub fn tcp_connect(net: &mut dyn Net, to: &SockAddr, from: Ip) -> SockResult<Socket> {
    let s = net.socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0)?;
    let mut r = if from != 0 { net.bind(s, &SockAddr::v4(from, 0)) } else { Ok(()) };
    if r.is_ok() {
        r = match net.connect(s, to) {
            Err(Errno::EINPROGRESS) => Ok(()),
            r => r,
        };
    }
    on_error(net, s, r)
}

/// A UDP socket on `port` (0: an ephemeral one), any address, allowed to
/// send broadcasts.
pub fn udp_bind(net: &mut dyn Net, port: u16) -> SockResult<Socket> {
    let s = net.socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0)?;
    let r = net.setsockopt(s, SOL_SOCKET, SO_BROADCAST, &1i32.to_ne_bytes()).and_then(|()| net.bind(s, &SockAddr::v4(0, port)));
    on_error(net, s, r)
}

fn on_error(net: &mut dyn Net, s: Socket, r: SockResult<()>) -> SockResult<Socket> {
    match r {
        Ok(()) => Ok(s),
        Err(e) => {
            let _ = net.close(s);
            Err(e)
        }
    }
}

/// Ok(true) once a connect has finished, Ok(false) while the handshake is
/// going on, Err with the reason if it failed (or the connection is gone).
pub fn connected(net: &mut dyn Net, s: Socket) -> SockResult<bool> {
    match net.getpeername(s) {
        Ok(_) => Ok(true),
        Err(Errno::ENOTCONN) => {
            let (events, _) = net.sock_poll(s)?;
            if events & (EPOLLERR | EPOLLHUP) == 0 {
                return Ok(false);
            }
            let mut v = [0u8; 4];
            net.getsockopt(s, SOL_SOCKET, SO_ERROR, &mut v)?;
            match i32::from_ne_bytes(v) {
                0 => Err(Errno::ENOTCONN),
                e => Err(Errno(e)),
            }
        }
        Err(e) => Err(e),
    }
}

/// Close with a reset (SO_LINGER 0) instead of the FIN handshake.
pub fn abort(net: &mut dyn Net, s: Socket) {
    let linger: [i32; 2] = [1, 0];
    let mut b = [0u8; 8];
    b[..4].copy_from_slice(&linger[0].to_ne_bytes());
    b[4..].copy_from_slice(&linger[1].to_ne_bytes());
    let _ = net.setsockopt(s, SOL_SOCKET, SO_LINGER, &b);
    let _ = net.close(s);
}
