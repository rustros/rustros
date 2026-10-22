//! Guest side of the RustROS WebAssembly ABI (see `rustros_api::abi`).
//!
//! Implements `rustros_api::Sys` on top of the host imports, so an application
//! written against `rustros_api::Module` builds unchanged as a native built-in app or
//! as a module:
//!
//! ```ignore
//! rustros_guest::export_module!(echo::Echo::new());
//! // or, for apps that want raw frames (Module::on_frame):
//! rustros_guest::export_module!(my::Switch::new(), frames);
//! ```
//!
//! Privileged calls (reboot, network configuration, kernel updates, module
//! management) are not available to modules; they fail or panic here.

use std::cell::RefCell;

use rustros_api::abi::*;

use rustros_api::{
    Admin, Module, Base, Caps, ConnInfo, Frame, HEADROOM, Ip, Kv, KvError, Net, NetError, NetInfo, Packet, RawSocket,
    SocketAddr, StorageInfo, Sys, TcpListener, TcpStream, UdpSocket, UpdateInfo, Verdict,
};

mod ffi {
    #[link(wasm_import_module = "rustros")]
    unsafe extern "C" {
        pub fn now_ms() -> i64;
        pub fn random() -> i64;
        pub fn print(p: *const u8, n: usize);
        pub fn cmdline(p: *mut u8, cap: usize) -> i32;
        pub fn modules(p: *mut u8, cap: usize) -> i32;
        pub fn last_crash(p: *mut u8, cap: usize) -> i32;
        pub fn net_info(p: *mut u8) -> i32;
        pub fn arp_table(p: *mut u8, cap: usize) -> i32;
        pub fn tcp_connections(p: *mut u8, cap: usize) -> i32;
        pub fn udp_bind(port: i32) -> i64;
        pub fn udp_local_port(h: i64) -> i32;
        pub fn udp_send_to(h: i64, ip: i32, port: i32, p: *const u8, n: usize) -> i32;
        pub fn udp_recv_from(h: i64, p: *mut u8, cap: usize, from: *mut u8) -> i32;
        pub fn udp_close(h: i64);
        pub fn tcp_listen(port: i32) -> i64;
        pub fn tcp_unlisten(h: i64);
        pub fn tcp_accept(h: i64, peer: *mut u8) -> i64;
        pub fn tcp_connect(ip: i32, port: i32) -> i64;
        pub fn tcp_is_connected(h: i64) -> i32;
        pub fn tcp_read(h: i64, p: *mut u8, cap: usize) -> i32;
        pub fn tcp_write(h: i64, p: *const u8, n: usize) -> i32;
        pub fn tcp_close(h: i64);
        pub fn tcp_abort(h: i64);
        pub fn raw_open(proto: i32) -> i64;
        pub fn raw_recv(h: i64, p: *mut u8, cap: usize, src: *mut u8) -> i32;
        pub fn raw_send(h: i64, ip: i32, p: *const u8, n: usize) -> i32;
        pub fn raw_close(h: i64);
        pub fn mac(p: *mut u8) -> i32;
        pub fn send_frame(p: *const u8, n: usize) -> i32;
        pub fn kv_get(kp: *const u8, kn: usize, p: *mut u8, cap: usize) -> i32;
        pub fn kv_put(kp: *const u8, kn: usize, vp: *const u8, vn: usize) -> i32;
        pub fn kv_delete(kp: *const u8, kn: usize) -> i32;
        pub fn kv_keys(pp: *const u8, pn: usize, p: *mut u8, cap: usize) -> i32;
        pub fn storage_info(p: *mut u8) -> i32;
        pub fn update_info(p: *mut u8) -> i32;
    }
}

/// Call a "fill this buffer, return the full length" import, growing the
/// buffer if needed. None on a negative (error) result.
fn fetch(f: impl Fn(*mut u8, usize) -> i32) -> Option<Vec<u8>> {
    let mut buf = vec![0u8; 256];
    loop {
        let n = f(buf.as_mut_ptr(), buf.len());
        if n < 0 {
            return None;
        }
        if n as usize <= buf.len() {
            buf.truncate(n as usize);
            return Some(buf);
        }
        buf.resize(n as usize, 0);
    }
}

fn le32(b: &[u8]) -> u32 {
    u32::from_le_bytes(b[..4].try_into().unwrap())
}
fn le64(b: &[u8]) -> u64 {
    u64::from_le_bytes(b[..8].try_into().unwrap())
}

fn addr(b: &[u8; 8]) -> SocketAddr {
    SocketAddr { ip: le32(b), port: u16::from_le_bytes([b[4], b[5]]) }
}

thread_local! {
    /// Strings handed out as &'static str (app names), leaked once each.
    static INTERNED: RefCell<Vec<&'static str>> = const { RefCell::new(Vec::new()) };
}

fn intern(s: &str) -> &'static str {
    INTERNED.with(|t| {
        let mut t = t.borrow_mut();
        if let Some(x) = t.iter().find(|x| **x == s) {
            return *x;
        }
        let x: &'static str = Box::leak(s.to_string().into_boxed_str());
        t.push(x);
        x
    })
}

fn handle(r: i64) -> Result<u64, NetError> {
    if r < 0 { Err(to_net_err(r)) } else { Ok(r as u64) }
}

fn status(r: i32) -> Result<(), NetError> {
    if r < 0 { Err(to_net_err(r as i64)) } else { Ok(()) }
}

pub struct GuestSys {
    cmdline: String,
    caps: Caps,
}

impl GuestSys {
    fn new(caps: Caps) -> GuestSys {
        let c = fetch(|p, n| unsafe { ffi::cmdline(p, n) }).unwrap_or_default();
        GuestSys { cmdline: String::from_utf8_lossy(&c).into_owned(), caps }
    }
}

impl Base for GuestSys {
    fn now_ms(&self) -> u64 {
        unsafe { ffi::now_ms() as u64 }
    }
    fn print(&mut self, s: &str) {
        unsafe { ffi::print(s.as_ptr(), s.len()) }
    }
    fn random(&mut self) -> u64 {
        unsafe { ffi::random() as u64 }
    }
}

impl Sys for GuestSys {
    fn cmdline(&self) -> &str {
        &self.cmdline
    }
    fn modules(&self) -> Vec<&'static str> {
        let b = fetch(|p, n| unsafe { ffi::modules(p, n) }).unwrap_or_default();
        String::from_utf8_lossy(&b).lines().map(intern).collect()
    }
    fn update_info(&self) -> Option<UpdateInfo> {
        let mut b = [0u8; UPDATE_INFO_LEN];
        if unsafe { ffi::update_info(b.as_mut_ptr()) } < 0 {
            return None;
        }
        Some(UpdateInfo {
            slot: b[0] as char,
            trial: b[1] == 1,
            safe_mode: b[2] == 1,
            unstable_boots: b[3] as u32,
            max_bytes: le64(&b[8..]),
        })
    }
    fn last_crash(&self) -> Option<String> {
        fetch(|p, n| unsafe { ffi::last_crash(p, n) }).map(|b| String::from_utf8_lossy(&b).into_owned())
    }
    fn caps(&self) -> Caps {
        self.caps
    }
    fn net(&mut self) -> Option<&mut dyn Net> {
        Some(self)
    }
    fn kv(&mut self) -> Option<&mut dyn Kv> {
        Some(self)
    }
    fn packet(&mut self) -> Option<&mut dyn Packet> {
        if self.caps.contains(Caps::PACKET) { Some(self) } else { None }
    }
    /// Never granted to WebAssembly apps.
    fn admin(&mut self) -> Option<&mut dyn Admin> {
        None
    }
}

impl Net for GuestSys {
    fn net_info(&self) -> NetInfo {
        let mut b = [0u8; NET_INFO_LEN];
        unsafe { ffi::net_info(b.as_mut_ptr()) };
        NetInfo {
            mac: b[..6].try_into().unwrap(),
            ip: le32(&b[8..]),
            mask: le32(&b[12..]),
            gw: le32(&b[16..]),
            mtu: le32(&b[20..]) as usize,
            rx: le64(&b[24..]),
            tx: le64(&b[32..]),
            rx_dropped: le64(&b[40..]),
            tx_dropped: le64(&b[48..]),
        }
    }
    fn arp_table(&self) -> Vec<(Ip, [u8; 6], u64)> {
        let b = fetch(|p, n| unsafe { ffi::arp_table(p, n) }).unwrap_or_default();
        b.chunks_exact(ARP_ENTRY_LEN).map(|e| (le32(e), e[4..10].try_into().unwrap(), le32(&e[12..]) as u64)).collect()
    }
    fn tcp_connections(&self) -> Vec<ConnInfo> {
        let b = fetch(|p, n| unsafe { ffi::tcp_connections(p, n) }).unwrap_or_default();
        String::from_utf8_lossy(&b)
            .lines()
            .filter_map(|l| {
                let f: Vec<&str> = l.split(' ').collect();
                if f.len() != 5 {
                    return None;
                }
                Some(ConnInfo {
                    local_port: f[0].parse().ok()?,
                    remote: SocketAddr { ip: f[1].parse().ok()?, port: f[2].parse().ok()? },
                    state: intern(f[3]),
                    owner: (f[4] != "-").then(|| intern(f[4])),
                })
            })
            .collect()
    }
    fn udp_bind(&mut self, port: u16) -> Result<UdpSocket, NetError> {
        handle(unsafe { ffi::udp_bind(port as i32) }).map(UdpSocket::from_raw)
    }
    fn udp_local_port(&self, s: UdpSocket) -> Result<u16, NetError> {
        let r = unsafe { ffi::udp_local_port(s.to_raw() as i64) };
        if r < 0 { Err(to_net_err(r as i64)) } else { Ok(r as u16) }
    }
    fn udp_send_to(&mut self, s: UdpSocket, to: SocketAddr, data: &[u8]) -> Result<(), NetError> {
        status(unsafe { ffi::udp_send_to(s.to_raw() as i64, to.ip as i32, to.port as i32, data.as_ptr(), data.len()) })
    }
    fn udp_recv_from(&mut self, s: UdpSocket, buf: &mut [u8]) -> Result<(usize, SocketAddr), NetError> {
        let mut from = [0u8; 8];
        let r = unsafe { ffi::udp_recv_from(s.to_raw() as i64, buf.as_mut_ptr(), buf.len(), from.as_mut_ptr()) };
        if r < 0 { Err(to_net_err(r as i64)) } else { Ok((r as usize, addr(&from))) }
    }
    fn udp_close(&mut self, s: UdpSocket) {
        unsafe { ffi::udp_close(s.to_raw() as i64) }
    }
    fn tcp_listen(&mut self, port: u16) -> Result<TcpListener, NetError> {
        handle(unsafe { ffi::tcp_listen(port as i32) }).map(TcpListener::from_raw)
    }
    fn tcp_unlisten(&mut self, l: TcpListener) {
        unsafe { ffi::tcp_unlisten(l.to_raw() as i64) }
    }
    fn tcp_accept(&mut self, l: TcpListener) -> Result<(TcpStream, SocketAddr), NetError> {
        let mut peer = [0u8; 8];
        let h = handle(unsafe { ffi::tcp_accept(l.to_raw() as i64, peer.as_mut_ptr()) })?;
        Ok((TcpStream::from_raw(h), addr(&peer)))
    }
    fn tcp_connect(&mut self, to: SocketAddr) -> Result<TcpStream, NetError> {
        handle(unsafe { ffi::tcp_connect(to.ip as i32, to.port as i32) }).map(TcpStream::from_raw)
    }
    fn tcp_is_connected(&self, s: TcpStream) -> Result<bool, NetError> {
        let r = unsafe { ffi::tcp_is_connected(s.to_raw() as i64) };
        if r < 0 { Err(to_net_err(r as i64)) } else { Ok(r == 1) }
    }
    fn tcp_read(&mut self, s: TcpStream, buf: &mut [u8]) -> Result<usize, NetError> {
        let r = unsafe { ffi::tcp_read(s.to_raw() as i64, buf.as_mut_ptr(), buf.len()) };
        if r < 0 { Err(to_net_err(r as i64)) } else { Ok(r as usize) }
    }
    fn tcp_write(&mut self, s: TcpStream, data: &[u8]) -> Result<usize, NetError> {
        let r = unsafe { ffi::tcp_write(s.to_raw() as i64, data.as_ptr(), data.len()) };
        if r < 0 { Err(to_net_err(r as i64)) } else { Ok(r as usize) }
    }
    fn tcp_close(&mut self, s: TcpStream) {
        unsafe { ffi::tcp_close(s.to_raw() as i64) }
    }
    fn tcp_abort(&mut self, s: TcpStream) {
        unsafe { ffi::tcp_abort(s.to_raw() as i64) }
    }
    fn raw_open(&mut self, proto: u8) -> Result<RawSocket, NetError> {
        handle(unsafe { ffi::raw_open(proto as i32) }).map(RawSocket::from_raw)
    }
    fn raw_recv(&mut self, s: RawSocket, buf: &mut [u8]) -> Result<(usize, Ip, u8), NetError> {
        let mut meta = [0u8; 8];
        let r = unsafe { ffi::raw_recv(s.to_raw() as i64, buf.as_mut_ptr(), buf.len(), meta.as_mut_ptr()) };
        if r < 0 { Err(to_net_err(r as i64)) } else { Ok((r as usize, le32(&meta), meta[4])) }
    }
    fn raw_send(&mut self, s: RawSocket, dst: Ip, payload: &[u8]) -> Result<(), NetError> {
        status(unsafe { ffi::raw_send(s.to_raw() as i64, dst as i32, payload.as_ptr(), payload.len()) })
    }
    fn raw_close(&mut self, s: RawSocket) {
        unsafe { ffi::raw_close(s.to_raw() as i64) }
    }
}

impl Kv for GuestSys {
    fn get(&self, key: &str) -> Option<Vec<u8>> {
        fetch(|p, n| unsafe { ffi::kv_get(key.as_ptr(), key.len(), p, n) })
    }
    fn put(&mut self, key: &str, value: &[u8]) -> Result<(), KvError> {
        let r = unsafe { ffi::kv_put(key.as_ptr(), key.len(), value.as_ptr(), value.len()) };
        if r < 0 { Err(to_kv_err(r)) } else { Ok(()) }
    }
    fn delete(&mut self, key: &str) -> Result<bool, KvError> {
        let r = unsafe { ffi::kv_delete(key.as_ptr(), key.len()) };
        if r < 0 { Err(to_kv_err(r)) } else { Ok(r == 1) }
    }
    fn keys(&self, prefix: &str) -> Vec<String> {
        let b = fetch(|p, n| unsafe { ffi::kv_keys(prefix.as_ptr(), prefix.len(), p, n) }).unwrap_or_default();
        String::from_utf8_lossy(&b).lines().map(String::from).collect()
    }
    fn storage_info(&self) -> Option<StorageInfo> {
        let mut b = [0u8; STORAGE_INFO_LEN];
        if unsafe { ffi::storage_info(b.as_mut_ptr()) } < 0 {
            return None;
        }
        Some(StorageInfo {
            partition_bytes: le64(&b),
            store_bytes: le64(&b[8..]),
            live_bytes: le64(&b[16..]),
            log_bytes: le64(&b[24..]),
        })
    }
}

impl Packet for GuestSys {
    fn mac(&self) -> [u8; 6] {
        let mut m = [0u8; 6];
        unsafe { ffi::mac(m.as_mut_ptr()) };
        m
    }
    fn send_frame(&mut self, frame: &[u8]) -> bool {
        unsafe { ffi::send_frame(frame.as_ptr(), frame.len()) == 1 }
    }
}

// ---------------------------------------------------------------- entry points

thread_local! {
    static STATE: RefCell<Option<(Box<dyn Module>, GuestSys)>> = const { RefCell::new(None) };
    static FRAME: RefCell<Box<[u8; HEADROOM + FRAME_BUF]>> = RefCell::new(Box::new([0; HEADROOM + FRAME_BUF]));
}

fn with_app(f: impl FnOnce(&mut dyn Module, &mut GuestSys)) {
    STATE.with(|s| {
        if let Some((app, sys)) = s.borrow_mut().as_mut() {
            f(app.as_mut(), sys);
        }
    });
}

#[doc(hidden)]
pub fn start(make: impl FnOnce() -> Box<dyn Module>, frames: bool) {
    // report the panic message before the trap that ends this instance
    std::panic::set_hook(Box::new(|info| {
        let msg = format!("panic: {info}\n");
        unsafe { ffi::print(msg.as_ptr(), msg.len()) }
    }));
    let caps = if frames { Caps::NET | Caps::KV | Caps::PACKET } else { Caps::NET | Caps::KV };
    let mut sys = GuestSys::new(caps);
    let mut app = make();
    app.start(&mut sys);
    STATE.with(|s| *s.borrow_mut() = Some((app, sys)));
}

#[doc(hidden)]
pub fn poll() {
    with_app(|app, sys| app.poll(sys));
}

#[doc(hidden)]
pub fn key(c: u8) {
    with_app(|app, sys| app.key(sys, c));
}

#[doc(hidden)]
pub fn frame_buf() -> usize {
    FRAME.with(|f| f.borrow().as_ptr() as usize)
}

/// Run the frame the host put at `buf + HEADROOM` through the app; returns
/// the verdict in the ABI's encoding (see `rustros_api::abi::EXPORT_FRAME`).
#[doc(hidden)]
pub fn frame(len: usize) -> i32 {
    FRAME.with(|f| {
        let mut buf = f.borrow_mut();
        let mut frame = Frame::new(&mut buf[..], HEADROOM, len.min(FRAME_BUF));
        with_app(|app, sys| app.on_frames(sys, core::slice::from_mut(&mut frame)));
        match frame.verdict {
            Verdict::Pass => FRAME_PASS,
            Verdict::Drop => FRAME_DROP,
            Verdict::Consumed => FRAME_CONSUMED,
            Verdict::Transmit => ((frame.headroom() as i32) << 16) | frame.len() as i32,
        }
    })
}

#[doc(hidden)]
pub const FRAMES: bool = false;

/// Export an `Module` as a RustROS WebAssembly module. Add `, frames` if the app
/// implements `on_frame` (the host then copies every received frame into it).
#[macro_export]
macro_rules! export_module {
    ($ctor:expr) => {
        #[unsafe(no_mangle)]
        pub extern "C" fn rustros_start() {
            $crate::start(|| ::std::boxed::Box::new($ctor), $crate::FRAMES)
        }
        #[unsafe(no_mangle)]
        pub extern "C" fn rustros_poll() {
            $crate::poll()
        }
        #[unsafe(no_mangle)]
        pub extern "C" fn rustros_key(c: i32) {
            $crate::key(c as u8)
        }
    };
    ($ctor:expr, frames) => {
        #[unsafe(no_mangle)]
        pub extern "C" fn rustros_start() {
            $crate::start(|| ::std::boxed::Box::new($ctor), true)
        }
        #[unsafe(no_mangle)]
        pub extern "C" fn rustros_poll() {
            $crate::poll()
        }
        #[unsafe(no_mangle)]
        pub extern "C" fn rustros_key(c: i32) {
            $crate::key(c as u8)
        }
        #[unsafe(no_mangle)]
        pub extern "C" fn rustros_frame_buf() -> i32 {
            $crate::frame_buf() as i32
        }
        #[unsafe(no_mangle)]
        pub extern "C" fn rustros_frame(len: i32) -> i32 {
            $crate::frame(len as usize)
        }
    };
}
