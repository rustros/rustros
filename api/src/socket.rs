//! Sockets with Linux semantics: the calls, flags, option names and error
//! numbers are Linux's (x86_64 values), so a Linux compatibility layer can
//! pass them straight through.
//!
//! Covered: IPv4 TCP, UDP and raw sockets of the network stack. The address
//! types leave room for IPv6 (`AF_INET6` sockets get `EAFNOSUPPORT` until
//! the stack has IPv6). NOT covered: Unix domain sockets (`AF_UNIX`: path
//! names, `SCM_RIGHTS`, `SO_PEERCRED`) — they belong to the VFS / process
//! layer, and get `EAFNOSUPPORT` here.
//!
//! Sockets never block: a call that would wait returns `EAGAIN` (or
//! `EINPROGRESS` for `connect`). Blocking, timeouts and signals (`SIGPIPE`
//! on `EPIPE` unless `MSG_NOSIGNAL`) are the process layer's business; the
//! flags for them (`SOCK_NONBLOCK`, `SOCK_CLOEXEC`, `MSG_NOSIGNAL`) are
//! accepted and kept for it.
//!
//! Readiness is pushed, not only queried: the stack reports every change of
//! a socket (data arrived, send space freed, connected, peer closed, error,
//! a connection to accept) as `EPOLL*` event bits, and bumps the socket's
//! event counter. Waiters register (or note the counter) first, check
//! `poll` second and sleep last, so a wakeup cannot be lost.

use core::fmt;

/// A socket, issued by the system to one application.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct Socket(u64);

impl Socket {
    pub fn to_raw(self) -> u64 {
        self.0
    }
    pub fn from_raw(raw: u64) -> Socket {
        Socket(raw)
    }
}

/// An epoll instance of one application.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Epoll(u64);

impl Epoll {
    pub fn to_raw(self) -> u64 {
        self.0
    }
    pub fn from_raw(raw: u64) -> Epoll {
        Epoll(raw)
    }
}

/// A Linux error number.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Errno(pub i32);

pub type SockResult<T> = Result<T, Errno>;

impl Errno {
    pub const EPERM: Errno = Errno(1);
    pub const ENOENT: Errno = Errno(2);
    pub const EINTR: Errno = Errno(4);
    pub const EBADF: Errno = Errno(9);
    pub const EAGAIN: Errno = Errno(11);
    pub const ENOMEM: Errno = Errno(12);
    pub const EACCES: Errno = Errno(13);
    pub const EFAULT: Errno = Errno(14);
    pub const EEXIST: Errno = Errno(17);
    pub const EINVAL: Errno = Errno(22);
    pub const EMFILE: Errno = Errno(24);
    pub const ENOTTY: Errno = Errno(25);
    pub const EPIPE: Errno = Errno(32);
    pub const ENOSYS: Errno = Errno(38);
    pub const ENOTSOCK: Errno = Errno(88);
    pub const EDESTADDRREQ: Errno = Errno(89);
    pub const EMSGSIZE: Errno = Errno(90);
    pub const EPROTOTYPE: Errno = Errno(91);
    pub const ENOPROTOOPT: Errno = Errno(92);
    pub const EPROTONOSUPPORT: Errno = Errno(93);
    pub const ESOCKTNOSUPPORT: Errno = Errno(94);
    pub const EOPNOTSUPP: Errno = Errno(95);
    pub const EAFNOSUPPORT: Errno = Errno(97);
    pub const EADDRINUSE: Errno = Errno(98);
    pub const EADDRNOTAVAIL: Errno = Errno(99);
    pub const ENETDOWN: Errno = Errno(100);
    pub const ENETUNREACH: Errno = Errno(101);
    pub const ECONNABORTED: Errno = Errno(103);
    pub const ECONNRESET: Errno = Errno(104);
    pub const ENOBUFS: Errno = Errno(105);
    pub const EISCONN: Errno = Errno(106);
    pub const ENOTCONN: Errno = Errno(107);
    pub const ESHUTDOWN: Errno = Errno(108);
    pub const ETIMEDOUT: Errno = Errno(110);
    pub const ECONNREFUSED: Errno = Errno(111);
    pub const EHOSTUNREACH: Errno = Errno(113);
    pub const EALREADY: Errno = Errno(114);
    pub const EINPROGRESS: Errno = Errno(115);

    /// The name, for messages ("EAGAIN"); "E?" for one not listed here.
    pub fn name(self) -> &'static str {
        match self.0 {
            1 => "EPERM",
            2 => "ENOENT",
            4 => "EINTR",
            9 => "EBADF",
            11 => "EAGAIN",
            12 => "ENOMEM",
            13 => "EACCES",
            14 => "EFAULT",
            17 => "EEXIST",
            22 => "EINVAL",
            24 => "EMFILE",
            25 => "ENOTTY",
            32 => "EPIPE",
            38 => "ENOSYS",
            88 => "ENOTSOCK",
            89 => "EDESTADDRREQ",
            90 => "EMSGSIZE",
            91 => "EPROTOTYPE",
            92 => "ENOPROTOOPT",
            93 => "EPROTONOSUPPORT",
            94 => "ESOCKTNOSUPPORT",
            95 => "EOPNOTSUPP",
            97 => "EAFNOSUPPORT",
            98 => "EADDRINUSE",
            99 => "EADDRNOTAVAIL",
            100 => "ENETDOWN",
            101 => "ENETUNREACH",
            103 => "ECONNABORTED",
            104 => "ECONNRESET",
            105 => "ENOBUFS",
            106 => "EISCONN",
            107 => "ENOTCONN",
            108 => "ESHUTDOWN",
            110 => "ETIMEDOUT",
            111 => "ECONNREFUSED",
            113 => "EHOSTUNREACH",
            114 => "EALREADY",
            115 => "EINPROGRESS",
            _ => "E?",
        }
    }
}

impl fmt::Display for Errno {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} ({})", self.name(), self.0)
    }
}

// address families
pub const AF_UNSPEC: i32 = 0;
pub const AF_UNIX: i32 = 1;
pub const AF_INET: i32 = 2;
pub const AF_INET6: i32 = 10;

// socket types, and the flags that may be or'ed into them (as accept4's flags)
pub const SOCK_STREAM: i32 = 1;
pub const SOCK_DGRAM: i32 = 2;
pub const SOCK_RAW: i32 = 3;
pub const SOCK_NONBLOCK: i32 = 0o4000;
pub const SOCK_CLOEXEC: i32 = 0o2000000;

// protocols
pub const IPPROTO_IP: i32 = 0;
pub const IPPROTO_ICMP: i32 = 1;
pub const IPPROTO_TCP: i32 = 6;
pub const IPPROTO_UDP: i32 = 17;
pub const IPPROTO_IPV6: i32 = 41;
pub const IPPROTO_ICMPV6: i32 = 58;
pub const IPPROTO_RAW: i32 = 255;

// send / recv flags
pub const MSG_OOB: i32 = 0x1;
pub const MSG_PEEK: i32 = 0x2;
pub const MSG_DONTROUTE: i32 = 0x4;
pub const MSG_TRUNC: i32 = 0x20;
pub const MSG_DONTWAIT: i32 = 0x40;
pub const MSG_EOR: i32 = 0x80;
pub const MSG_WAITALL: i32 = 0x100;
pub const MSG_NOSIGNAL: i32 = 0x4000;
pub const MSG_MORE: i32 = 0x8000;

// shutdown
pub const SHUT_RD: i32 = 0;
pub const SHUT_WR: i32 = 1;
pub const SHUT_RDWR: i32 = 2;

// socket options: level SOL_SOCKET
pub const SOL_SOCKET: i32 = 1;
pub const SO_REUSEADDR: i32 = 2;
pub const SO_TYPE: i32 = 3;
pub const SO_ERROR: i32 = 4;
pub const SO_BROADCAST: i32 = 6;
pub const SO_SNDBUF: i32 = 7;
pub const SO_RCVBUF: i32 = 8;
pub const SO_KEEPALIVE: i32 = 9;
pub const SO_LINGER: i32 = 13;
/// Several sockets on one address and port (connections spread among them).
pub const SO_REUSEPORT: i32 = 15;
pub const SO_RCVTIMEO: i32 = 20;
pub const SO_SNDTIMEO: i32 = 21;
pub const SO_BINDTODEVICE: i32 = 25;
pub const SO_ACCEPTCONN: i32 = 30;
pub const SO_PROTOCOL: i32 = 38;
pub const SO_DOMAIN: i32 = 39;
// level IPPROTO_TCP
pub const TCP_NODELAY: i32 = 1;
pub const TCP_MAXSEG: i32 = 2;
pub const TCP_KEEPIDLE: i32 = 4;
pub const TCP_KEEPINTVL: i32 = 5;
pub const TCP_KEEPCNT: i32 = 6;
// level IPPROTO_IP
pub const IP_TOS: i32 = 1;
pub const IP_TTL: i32 = 2;
pub const IP_HDRINCL: i32 = 3;

// ioctl requests
/// Bytes waiting to be read (TCP), or the size of the next datagram (UDP).
pub const FIONREAD: u32 = 0x541B;
pub const SIOCINQ: u32 = FIONREAD;
/// Bytes not yet sent (TCP: not yet acknowledged).
pub const SIOCOUTQ: u32 = 0x5411;
pub const FIONBIO: u32 = 0x5421;

// readiness (epoll / poll; the low bits are poll's POLL* values)
pub const EPOLLIN: u32 = 0x001;
pub const EPOLLPRI: u32 = 0x002;
pub const EPOLLOUT: u32 = 0x004;
pub const EPOLLERR: u32 = 0x008;
pub const EPOLLHUP: u32 = 0x010;
pub const EPOLLRDNORM: u32 = 0x040;
pub const EPOLLWRNORM: u32 = 0x100;
pub const EPOLLRDHUP: u32 = 0x2000;
pub const EPOLLEXCLUSIVE: u32 = 1 << 28;
pub const EPOLLONESHOT: u32 = 1 << 30;
pub const EPOLLET: u32 = 1 << 31;
pub const EPOLL_CTL_ADD: i32 = 1;
pub const EPOLL_CTL_DEL: i32 = 2;
pub const EPOLL_CTL_MOD: i32 = 3;

/// One ready entry from `epoll_wait`: the events and the caller's data.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct EpollEvent {
    pub events: u32,
    pub data: u64,
}

/// An IP address of either family.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum IpAddr {
    V4([u8; 4]),
    V6([u8; 16]),
}

/// A socket address, field for field `sockaddr_in` / `sockaddr_in6` (host
/// byte order for the port). More families may follow (`AF_UNIX` paths).
#[non_exhaustive]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SockAddr {
    V4 { addr: [u8; 4], port: u16 },
    V6 { addr: [u8; 16], port: u16, flowinfo: u32, scope_id: u32 },
}

impl SockAddr {
    /// An IPv4 address from the stack's `Ip` (host order).
    pub fn v4(ip: u32, port: u16) -> SockAddr {
        SockAddr::V4 { addr: ip.to_be_bytes(), port }
    }

    pub fn family(&self) -> i32 {
        match self {
            SockAddr::V4 { .. } => AF_INET,
            SockAddr::V6 { .. } => AF_INET6,
        }
    }

    pub fn port(&self) -> u16 {
        match *self {
            SockAddr::V4 { port, .. } | SockAddr::V6 { port, .. } => port,
        }
    }

    pub fn ip(&self) -> IpAddr {
        match *self {
            SockAddr::V4 { addr, .. } => IpAddr::V4(addr),
            SockAddr::V6 { addr, .. } => IpAddr::V6(addr),
        }
    }

    /// The IPv4 address as the stack's `Ip`, if it is one.
    pub fn ipv4(&self) -> Option<u32> {
        match *self {
            SockAddr::V4 { addr, .. } => Some(u32::from_be_bytes(addr)),
            _ => None,
        }
    }
}

impl fmt::Display for SockAddr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            SockAddr::V4 { addr: a, port } => write!(f, "{}.{}.{}.{}:{}", a[0], a[1], a[2], a[3], port),
            SockAddr::V6 { addr, port, .. } => {
                f.write_str("[")?;
                for (i, w) in addr.chunks(2).enumerate() {
                    write!(f, "{}{:x}", if i > 0 { ":" } else { "" }, u16::from_be_bytes([w[0], w[1]]))?;
                }
                write!(f, "]:{port}")
            }
        }
    }
}
