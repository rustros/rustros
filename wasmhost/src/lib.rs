//! WebAssembly applications (wasmi interpreter).
//!
//! Each module instance is an application like the native ones: it gets its
//! own app id, so socket ownership and the key-value namespace work the same.
//! Unlike native apps it is isolated: a trap (panic, bad memory access) or an
//! exhausted time slice stops only this instance; the kernel then releases
//! its sockets and restarts it with exponential backoff. Instances also get a
//! memory cap, and privileged calls (reboot, network config, updates, module
//! management) are simply not importable.
//!
//! The ABI is described in `rustros_api::abi`; the guest side is `wasm/guest`.
//!
//! The one `unsafe` here lends the calling app's `Sys` to host functions for
//! the duration of a guest call (see `with_sys`).
#![no_std]

extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use rustros_api::abi::*;
use rustros_api::Ip;
use rustros_api::module::Runtime;
use rustros_api::{Caps, Frame, HEADROOM, Kv, Net, Packet, RawSocket, SocketAddr, Sys, TcpListener, TcpStream, UdpSocket, Verdict};
use wasmi::{Caller, Config, Linker, Memory, Module, Store, StoreLimits, StoreLimitsBuilder, TypedFunc};
pub use wasmi::Engine;

/// Instructions (roughly) one call into a guest may execute.
pub const FUEL_PER_CALL: u64 = 50_000_000;
pub const MEMORY_LIMIT: usize = 16 << 20;
const BACKOFF_MAX_MS: u64 = 60_000;
/// Running this long without trouble resets the backoff.
const STABLE_MS: u64 = 60_000;

pub fn engine() -> Engine {
    let mut c = Config::default();
    c.consume_fuel(true);
    Engine::new(&c)
}

/// The WebAssembly application runtime (see `rustros_api::module::Runtime`).
pub struct WasmRuntime {
    engine: Engine,
}

impl Default for WasmRuntime {
    fn default() -> Self {
        Self::new()
    }
}

impl WasmRuntime {
    pub fn new() -> WasmRuntime {
        WasmRuntime { engine: engine() }
    }
}

impl Runtime for WasmRuntime {
    fn format(&self) -> &'static str {
        "wasm"
    }
    fn accepts(&self, image: &[u8]) -> bool {
        image.starts_with(b"\0asm")
    }
    fn validate(&self, image: &[u8]) -> Result<(), String> {
        compile(&self.engine, image).map(|_| ())
    }
    fn instantiate(&mut self, name: &'static str, image: &[u8]) -> Result<alloc::boxed::Box<dyn rustros_api::Module>, String> {
        let module = compile(&self.engine, image)?;
        Ok(alloc::boxed::Box::new(WasmApp::new(&self.engine, name, module)))
    }
}

/// Capabilities a module gets: sockets and storage, plus the packet path if
/// it exports the frame hook. Never ADMIN.
pub fn caps(module: &Module) -> Caps {
    let base = Caps::NET | Caps::KV;
    if module.get_export(EXPORT_FRAME).is_some() { base | Caps::PACKET } else { base }
}

/// Compile and check a module: it must export memory and the entry points.
pub fn compile(engine: &Engine, bytes: &[u8]) -> Result<Module, String> {
    let module = Module::new(engine, bytes).map_err(|e| format!("invalid module: {e}"))?;
    for name in ["memory", EXPORT_START, EXPORT_POLL] {
        if module.get_export(name).is_none() {
            return Err(format!("module does not export `{name}` (built without rustros-guest?)"));
        }
    }
    Ok(module)
}

struct HostState {
    /// The calling app's `Sys`, set only while a guest call is running.
    sys: Option<*mut (dyn Sys + 'static)>,
    memory: Option<Memory>,
    limits: StoreLimits,
}

struct Running {
    store: Store<HostState>,
    poll: TypedFunc<(), ()>,
    key: Option<TypedFunc<i32, ()>>,
    frame: Option<(TypedFunc<i32, i32>, usize)>,
}

pub struct WasmApp {
    name: &'static str,
    engine: Engine,
    module: Module,
    run: Option<Running>,
    restarts: u32,
    retry_at: u64,
    backoff: u64,
    started_at: u64,
    last_error: Option<String>,
    /// Stopped since the kernel last looked: its resources must be released.
    needs_release: bool,
}

/// Make `sys` reachable from host functions for the duration of `f`.
fn with_sys<S, R>(
    state: &mut S,
    host: impl Fn(&mut S) -> &mut HostState,
    sys: &mut dyn Sys,
    f: impl FnOnce(&mut S) -> R,
) -> R {
    // Safety: the pointer is only dereferenced by host functions, which run
    // inside `f`, while `sys` stays mutably borrowed by this frame; it is
    // cleared before returning.
    let p: *mut (dyn Sys + '_) = sys;
    host(state).sys = Some(unsafe { core::mem::transmute::<*mut (dyn Sys + '_), *mut (dyn Sys + 'static)>(p) });
    let r = f(state);
    host(state).sys = None;
    r
}

impl WasmApp {
    pub fn new(engine: &Engine, name: &'static str, module: Module) -> WasmApp {
        WasmApp {
            name,
            engine: engine.clone(),
            module,
            run: None,
            restarts: 0,
            retry_at: 0,
            backoff: 1000,
            started_at: 0,
            last_error: None,
            needs_release: false,
        }
    }


    fn launch(&mut self, sys: &mut dyn Sys) -> Result<Running, wasmi::Error> {
        let limits = StoreLimitsBuilder::new().memory_size(MEMORY_LIMIT).instances(1).memories(1).tables(4).build();
        let mut store = Store::new(&self.engine, HostState { sys: None, memory: None, limits });
        store.limiter(|s| &mut s.limits);
        store.set_fuel(FUEL_PER_CALL)?;
        let linker = linker(&self.engine);
        let module = &self.module;
        let instance = with_sys(&mut store, |s| s.data_mut(), sys, |store| linker.instantiate_and_start(store, module))?;
        store.data_mut().memory = instance.get_memory(&store, "memory");
        let start = instance.get_typed_func::<(), ()>(&store, EXPORT_START)?;
        let poll = instance.get_typed_func::<(), ()>(&store, EXPORT_POLL)?;
        let key = instance.get_typed_func::<i32, ()>(&store, EXPORT_KEY).ok();
        let frame = match (
            instance.get_typed_func::<i32, i32>(&store, EXPORT_FRAME),
            instance.get_typed_func::<(), i32>(&store, EXPORT_FRAME_BUF),
        ) {
            (Ok(f), Ok(buf)) => {
                store.set_fuel(FUEL_PER_CALL)?;
                Some((f, buf.call(&mut store, ())? as u32 as usize))
            }
            _ => None,
        };
        store.set_fuel(FUEL_PER_CALL)?;
        with_sys(&mut store, |s| s.data_mut(), sys, |store| start.call(store, ()))?;
        Ok(Running { store, poll, key, frame })
    }

    fn stop(&mut self, sys: &mut dyn Sys, why: String) {
        let now = sys.now_ms();
        if now - self.started_at > STABLE_MS {
            self.backoff = 1000;
        }
        sys.print(&format!("wasm[{}]: stopped: {}; restart in {} s\n", self.name, why, self.backoff / 1000));
        self.run = None;
        self.restarts += 1;
        self.retry_at = now + self.backoff;
        self.backoff = (self.backoff * 2).min(BACKOFF_MAX_MS);
        self.last_error = Some(why);
        self.needs_release = true;
    }

    fn describe(e: &wasmi::Error) -> String {
        let s = format!("{e}");
        if s.contains("fuel") { format!("{s} (endless loop?)") } else { s }
    }

    /// Run one guest call; a trap stops the instance.
    fn call<R: Default>(&mut self, sys: &mut dyn Sys, f: impl FnOnce(&mut Running) -> Result<R, wasmi::Error>) -> R {
        let Some(run) = self.run.as_mut() else { return R::default() };
        let result = run
            .store
            .set_fuel(FUEL_PER_CALL)
            .and_then(|_| with_sys(run, |r| r.store.data_mut(), sys, f));
        result.unwrap_or_else(|e| {
            self.stop(sys, Self::describe(&e));
            R::default()
        })
    }

    fn ensure_running(&mut self, sys: &mut dyn Sys) {
        if self.run.is_some() || sys.now_ms() < self.retry_at {
            return;
        }
        self.started_at = sys.now_ms();
        match self.launch(sys) {
            Ok(run) => {
                self.run = Some(run);
            }
            Err(e) => self.stop(sys, Self::describe(&e)),
        }
    }
}

impl rustros_api::Module for WasmApp {
    fn name(&self) -> &'static str {
        self.name
    }

    fn start(&mut self, sys: &mut dyn Sys) {
        self.ensure_running(sys);
    }

    fn poll(&mut self, sys: &mut dyn Sys) {
        self.ensure_running(sys);
        self.call(sys, |run| {
            let f = run.poll;
            f.call(&mut run.store, ())
        });
    }

    fn key(&mut self, sys: &mut dyn Sys, c: u8) {
        self.call(sys, |run| match run.key {
            Some(k) => k.call(&mut run.store, c as i32),
            None => Ok(()),
        });
    }

    fn caps(&self) -> Caps {
        caps(&self.module)
    }

    fn take_restart(&mut self) -> bool {
        core::mem::take(&mut self.needs_release)
    }

    fn status(&self) -> String {
        match (&self.run, &self.last_error) {
            (Some(_), _) => String::from("running"),
            (None, e) => format!(
                "stopped ({}), restart pending",
                e.as_deref().unwrap_or("not started")
            ),
        }
    }

    fn restarts(&self) -> u32 {
        self.restarts
    }

    fn on_frames(&mut self, sys: &mut dyn Sys, frames: &mut [Frame]) {
        let Some((_, buf)) = self.run.as_ref().and_then(|r| r.frame) else { return };
        for frame in frames.iter_mut() {
            if self.run.is_none() {
                return; // trapped on an earlier frame
            }
            let len = frame.len().min(FRAME_BUF);
            let verdict = self.call(sys, |run| {
                let Some((f, _)) = run.frame else { return Ok(FRAME_PASS) };
                let mem = run.store.data().memory.ok_or_else(|| wasmi::Error::new("no memory"))?;
                let oob = |_| wasmi::Error::new("frame buffer out of bounds");
                mem.write(&mut run.store, buf + HEADROOM, &frame.data()[..len]).map_err(oob)?;
                let r = f.call(&mut run.store, len as i32)?;
                if r > 0 {
                    let (start, n) = ((r >> 16) as usize, (r & 0xFFFF) as usize);
                    let mut out = vec![0u8; n];
                    mem.read(&run.store, buf + start, &mut out).map_err(oob)?;
                    return Ok(if frame.set_data(&out) { 1 } else { FRAME_DROP });
                }
                Ok(r)
            });
            frame.verdict = match verdict {
                FRAME_DROP => Verdict::Drop,
                FRAME_CONSUMED => Verdict::Consumed,
                v if v > 0 => Verdict::Transmit,
                _ => Verdict::Pass,
            };
        }
    }
}

// ---------------------------------------------------------------- host functions

type C<'a> = Caller<'a, HostState>;

fn sys<'a>(c: &C<'_>) -> &'a mut dyn Sys {
    // Safety: see `with_sys`; host functions only run inside guest calls.
    unsafe { &mut *c.data().sys.expect("host function called outside a guest call") }
}

// Capability-checked views; a call without the capability gets E_DENIED.
macro_rules! net {
    ($c:expr) => {
        match net(&$c) {
            Some(n) => n,
            None => return denied(),
        }
    };
}
macro_rules! kv {
    ($c:expr) => {
        match kv(&$c) {
            Some(k) => k,
            None => return denied(),
        }
    };
}
macro_rules! packet {
    ($c:expr) => {
        match packet(&$c) {
            Some(p) => p,
            None => return denied(),
        }
    };
}

/// E_DENIED as whatever integer type the host function returns (unit for
/// the ones that return nothing).
fn denied<T: Denied>() -> T {
    T::denied()
}
trait Denied {
    fn denied() -> Self;
}
impl Denied for i32 {
    fn denied() -> i32 {
        E_DENIED
    }
}
impl Denied for i64 {
    fn denied() -> i64 {
        E_DENIED as i64
    }
}
impl Denied for () {
    fn denied() {}
}
fn net<'a>(c: &C<'_>) -> Option<&'a mut dyn Net> {
    sys(c).net()
}
fn kv<'a>(c: &C<'_>) -> Option<&'a mut dyn Kv> {
    sys(c).kv()
}
fn packet<'a>(c: &C<'_>) -> Option<&'a mut dyn Packet> {
    sys(c).packet()
}

/// Copy `len` bytes from guest memory.
fn read(c: &C<'_>, ptr: i32, len: i32) -> Option<Vec<u8>> {
    if !(0..=MEMORY_LIMIT as i32).contains(&len) {
        return None;
    }
    let mut v = vec![0u8; len as usize];
    c.data().memory?.read(c, ptr as u32 as usize, &mut v).ok()?;
    Some(v)
}

fn read_str(c: &C<'_>, ptr: i32, len: i32) -> Option<String> {
    String::from_utf8(read(c, ptr, len)?).ok()
}

fn write(c: &mut C<'_>, ptr: i32, data: &[u8]) -> bool {
    match c.data().memory {
        Some(m) => m.write(c, ptr as u32 as usize, data).is_ok(),
        None => false,
    }
}

/// Copy `data` into a guest buffer of `cap` bytes (truncating); returns the
/// full length so the guest can retry with a bigger buffer.
fn give(c: &mut C<'_>, ptr: i32, cap: i32, data: &[u8]) -> i32 {
    let n = data.len().min(cap.max(0) as usize);
    if !write(c, ptr, &data[..n]) {
        return E_FAULT;
    }
    data.len() as i32
}

fn handle<T>(r: Result<T, rustros_api::NetError>, raw: impl Fn(T) -> u64) -> i64 {
    match r {
        Ok(h) => raw(h) as i64,
        Err(e) => net_err(e) as i64,
    }
}

fn status(r: Result<(), rustros_api::NetError>) -> i32 {
    match r {
        Ok(()) => 0,
        Err(e) => net_err(e),
    }
}

fn linker(engine: &Engine) -> Linker<HostState> {
    let mut l = Linker::<HostState>::new(engine);
    let m = MODULE;
    // general
    l.func_wrap(m, "now_ms", |c: C| sys(&c).now_ms() as i64).unwrap();
    l.func_wrap(m, "random", |c: C| sys(&c).random() as i64).unwrap();
    l.func_wrap(m, "print", |c: C, p: i32, n: i32| {
        if let Some(b) = read(&c, p, n) {
            sys(&c).print(&String::from_utf8_lossy(&b));
        }
    })
    .unwrap();
    l.func_wrap(m, "cmdline", |mut c: C, p: i32, cap: i32| {
        let s = String::from(sys(&c).cmdline());
        give(&mut c, p, cap, s.as_bytes())
    })
    .unwrap();
    l.func_wrap(m, "modules", |mut c: C, p: i32, cap: i32| {
        let s = sys(&c).modules().join("\n");
        give(&mut c, p, cap, s.as_bytes())
    })
    .unwrap();
    l.func_wrap(m, "last_crash", |mut c: C, p: i32, cap: i32| match sys(&c).last_crash() {
        Some(s) => give(&mut c, p, cap, s.as_bytes()),
        None => E_NOT_FOUND,
    })
    .unwrap();
    // network status
    l.func_wrap(m, "net_info", |mut c: C, p: i32| {
        let n = net!(c).net_info();
        let mut b = Vec::with_capacity(NET_INFO_LEN);
        b.extend_from_slice(&n.mac);
        b.extend_from_slice(&[0, 0]);
        for v in [n.ip, n.mask, n.gw, n.mtu as u32] {
            b.extend_from_slice(&v.to_le_bytes());
        }
        for v in [n.rx, n.tx, n.rx_dropped, n.tx_dropped] {
            b.extend_from_slice(&v.to_le_bytes());
        }
        if write(&mut c, p, &b) { 0 } else { E_FAULT }
    })
    .unwrap();
    l.func_wrap(m, "arp_table", |mut c: C, p: i32, cap: i32| {
        let mut b = Vec::new();
        for (ip, mac, age) in net!(c).arp_table() {
            b.extend_from_slice(&ip.to_le_bytes());
            b.extend_from_slice(&mac);
            b.extend_from_slice(&[0, 0]);
            b.extend_from_slice(&(age.min(u32::MAX as u64) as u32).to_le_bytes());
        }
        give(&mut c, p, cap, &b)
    })
    .unwrap();
    l.func_wrap(m, "tcp_connections", |mut c: C, p: i32, cap: i32| {
        let mut s = String::new();
        for x in net!(c).tcp_connections() {
            s += &format!("{} {} {} {} {}\n", x.local_port, x.remote.ip, x.remote.port, x.state, x.owner.unwrap_or("-"));
        }
        give(&mut c, p, cap, s.as_bytes())
    })
    .unwrap();
    // UDP
    l.func_wrap(m, "udp_bind", |c: C, port: i32| handle(net!(c).udp_bind(port as u16), UdpSocket::to_raw)).unwrap();
    l.func_wrap(m, "udp_local_port", |c: C, h: i64| match net!(c).udp_local_port(UdpSocket::from_raw(h as u64)) {
        Ok(p) => p as i32,
        Err(e) => net_err(e),
    })
    .unwrap();
    l.func_wrap(m, "udp_send_to", |c: C, h: i64, ip: i32, port: i32, p: i32, n: i32| {
        let Some(data) = read(&c, p, n) else { return E_FAULT };
        let to = SocketAddr { ip: ip as u32, port: port as u16 };
        status(net!(c).udp_send_to(UdpSocket::from_raw(h as u64), to, &data))
    })
    .unwrap();
    l.func_wrap(m, "udp_recv_from", |mut c: C, h: i64, p: i32, cap: i32, from: i32| {
        let mut buf = vec![0u8; cap.clamp(0, 65536) as usize];
        match net!(c).udp_recv_from(UdpSocket::from_raw(h as u64), &mut buf) {
            Ok((n, a)) => {
                let mut addr = [0u8; 8];
                addr[..4].copy_from_slice(&a.ip.to_le_bytes());
                addr[4..6].copy_from_slice(&a.port.to_le_bytes());
                if write(&mut c, p, &buf[..n]) && write(&mut c, from, &addr) { n as i32 } else { E_FAULT }
            }
            Err(e) => net_err(e),
        }
    })
    .unwrap();
    l.func_wrap(m, "udp_close", |c: C, h: i64| net!(c).udp_close(UdpSocket::from_raw(h as u64))).unwrap();
    // TCP
    l.func_wrap(m, "tcp_listen", |c: C, port: i32| handle(net!(c).tcp_listen(port as u16), TcpListener::to_raw)).unwrap();
    l.func_wrap(m, "tcp_unlisten", |c: C, h: i64| net!(c).tcp_unlisten(TcpListener::from_raw(h as u64))).unwrap();
    l.func_wrap(m, "tcp_accept", |mut c: C, h: i64, peer: i32| match net!(c).tcp_accept(TcpListener::from_raw(h as u64)) {
        Ok((s, a)) => {
            let mut addr = [0u8; 8];
            addr[..4].copy_from_slice(&a.ip.to_le_bytes());
            addr[4..6].copy_from_slice(&a.port.to_le_bytes());
            if write(&mut c, peer, &addr) { s.to_raw() as i64 } else { E_FAULT as i64 }
        }
        Err(e) => net_err(e) as i64,
    })
    .unwrap();
    l.func_wrap(m, "tcp_connect", |c: C, ip: i32, port: i32| {
        handle(net!(c).tcp_connect(SocketAddr { ip: ip as u32, port: port as u16 }), TcpStream::to_raw)
    })
    .unwrap();
    l.func_wrap(m, "tcp_is_connected", |c: C, h: i64| match net!(c).tcp_is_connected(TcpStream::from_raw(h as u64)) {
        Ok(b) => b as i32,
        Err(e) => net_err(e),
    })
    .unwrap();
    l.func_wrap(m, "tcp_read", |mut c: C, h: i64, p: i32, cap: i32| {
        let mut buf = vec![0u8; cap.clamp(0, 65536) as usize];
        match net!(c).tcp_read(TcpStream::from_raw(h as u64), &mut buf) {
            Ok(n) => {
                if write(&mut c, p, &buf[..n]) { n as i32 } else { E_FAULT }
            }
            Err(e) => net_err(e),
        }
    })
    .unwrap();
    l.func_wrap(m, "tcp_write", |c: C, h: i64, p: i32, n: i32| {
        let Some(data) = read(&c, p, n) else { return E_FAULT };
        match net!(c).tcp_write(TcpStream::from_raw(h as u64), &data) {
            Ok(n) => n as i32,
            Err(e) => net_err(e),
        }
    })
    .unwrap();
    l.func_wrap(m, "tcp_close", |c: C, h: i64| net!(c).tcp_close(TcpStream::from_raw(h as u64))).unwrap();
    l.func_wrap(m, "tcp_abort", |c: C, h: i64| net!(c).tcp_abort(TcpStream::from_raw(h as u64))).unwrap();
    // raw IP
    l.func_wrap(m, "raw_open", |c: C, proto: i32| handle(net!(c).raw_open(proto as u8), RawSocket::to_raw)).unwrap();
    l.func_wrap(m, "raw_recv", |mut c: C, h: i64, p: i32, cap: i32, src: i32| {
        let mut buf = vec![0u8; cap.clamp(0, 65536) as usize];
        match net!(c).raw_recv(RawSocket::from_raw(h as u64), &mut buf) {
            Ok((n, ip, ttl)) => {
                let mut meta = [0u8; 8];
                meta[..4].copy_from_slice(&ip.to_le_bytes());
                meta[4] = ttl;
                if write(&mut c, p, &buf[..n]) && write(&mut c, src, &meta) { n as i32 } else { E_FAULT }
            }
            Err(e) => net_err(e),
        }
    })
    .unwrap();
    l.func_wrap(m, "raw_send", |c: C, h: i64, ip: i32, p: i32, n: i32| {
        let Some(data) = read(&c, p, n) else { return E_FAULT };
        status(net!(c).raw_send(RawSocket::from_raw(h as u64), ip as Ip, &data))
    })
    .unwrap();
    l.func_wrap(m, "raw_close", |c: C, h: i64| net!(c).raw_close(RawSocket::from_raw(h as u64))).unwrap();
    // Ethernet
    l.func_wrap(m, "mac", |mut c: C, p: i32| {
        let mac = packet!(c).mac();
        if write(&mut c, p, &mac) { 0 } else { E_FAULT }
    })
    .unwrap();
    l.func_wrap(m, "send_frame", |c: C, p: i32, n: i32| match read(&c, p, n.min(FRAME_BUF as i32)) {
        Some(f) => packet!(c).send_frame(&f) as i32,
        None => E_FAULT,
    })
    .unwrap();
    // key-value store
    l.func_wrap(m, "kv_get", |mut c: C, kp: i32, kn: i32, p: i32, cap: i32| {
        let Some(k) = read_str(&c, kp, kn) else { return E_FAULT };
        match kv!(c).get(&k) {
            Some(v) => give(&mut c, p, cap, &v),
            None => E_NOT_FOUND,
        }
    })
    .unwrap();
    l.func_wrap(m, "kv_put", |c: C, kp: i32, kn: i32, vp: i32, vn: i32| {
        let (Some(k), Some(v)) = (read_str(&c, kp, kn), read(&c, vp, vn)) else { return E_FAULT };
        match kv!(c).put(&k, &v) {
            Ok(()) => 0,
            Err(e) => kv_err(e),
        }
    })
    .unwrap();
    l.func_wrap(m, "kv_delete", |c: C, kp: i32, kn: i32| {
        let Some(k) = read_str(&c, kp, kn) else { return E_FAULT };
        match kv!(c).delete(&k) {
            Ok(b) => b as i32,
            Err(e) => kv_err(e),
        }
    })
    .unwrap();
    l.func_wrap(m, "kv_keys", |mut c: C, pp: i32, pn: i32, p: i32, cap: i32| {
        let Some(prefix) = read_str(&c, pp, pn) else { return E_FAULT };
        let s = kv!(c).keys(&prefix).join("\n");
        give(&mut c, p, cap, s.as_bytes())
    })
    .unwrap();
    l.func_wrap(m, "storage_info", |mut c: C, p: i32| match kv!(c).storage_info() {
        Some(i) => {
            let mut b = Vec::with_capacity(STORAGE_INFO_LEN);
            for v in [i.partition_bytes, i.store_bytes, i.live_bytes, i.log_bytes] {
                b.extend_from_slice(&v.to_le_bytes());
            }
            if write(&mut c, p, &b) { 0 } else { E_FAULT }
        }
        None => E_NO_STORAGE,
    })
    .unwrap();
    l.func_wrap(m, "update_info", |mut c: C, p: i32| match sys(&c).update_info() {
        Some(u) => {
            let mut b = vec![0u8; UPDATE_INFO_LEN];
            b[0] = u.slot as u8;
            b[1] = u.trial as u8;
            b[2] = u.safe_mode as u8;
            b[3] = u.unstable_boots.min(255) as u8;
            b[8..16].copy_from_slice(&u.max_bytes.to_le_bytes());
            if write(&mut c, p, &b) { 0 } else { E_FAULT }
        }
        None => E_NOT_FOUND,
    })
    .unwrap();
    l
}
