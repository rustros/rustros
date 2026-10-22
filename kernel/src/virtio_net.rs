//! virtio-net driver (polled; an interrupt wakes the CPU when idle).
//!
//! With VIRTIO_NET_F_MQ it uses several queue pairs: still one CPU, but
//! frames go out on a TX queue chosen by flow (packets of one connection
//! stay in order), so the host serves them with several threads, and the
//! host spreads what comes in over the RX queues. With CTRL_RX the host
//! drops unicast for other MACs itself (promiscuous mode off).
//!
//! Offloads (modern devices, if the host offers them and they are not turned
//! off): with GUEST_TSO4 the host hands over big TCP segments (GRO; spread
//! over several ring buffers with MRG_RXBUF and put back together here) and
//! partial checksums; with HOST_TSO4 / CSUM big segments and partial
//! checksums go out as they are and the host finishes them.
//!
//! Zero copy: every ring slot holds a packet buffer (`devices::Buf`). A
//! received frame's buffer is swapped for a spare one from the kernel, and a
//! forwarded frame's buffer goes onto the TX ring as it is, a spare one
//! going back; each queue keeps the same number of buffers.

use alloc::vec;
use alloc::vec::Vec;

use devices::{BUF_SIZE, Buf, HEADROOM, Offload, new_buf};

use crate::pci::PciDev;
use crate::virtio::{D_NEXT, D_WRITE, Queue, Virtio};

const F_CSUM: u64 = 1 << 0;
const F_GUEST_CSUM: u64 = 1 << 1;
const F_GUEST_TSO4: u64 = 1 << 7;
const F_GUEST_ECN: u64 = 1 << 9;
const F_HOST_TSO4: u64 = 1 << 11;
const F_HOST_ECN: u64 = 1 << 13;
const F_MRG_RXBUF: u64 = 1 << 15;
const F_MAC: u64 = 1 << 5;
/// virtio_net_hdr
const NEEDS_CSUM: u8 = 1;
const GSO_TCPV4: u8 = 1;
const GSO_ECN: u8 = 0x80;
const F_CTRL_VQ: u64 = 1 << 17;
const F_CTRL_RX: u64 = 1 << 18;
const F_MQ: u64 = 1 << 22;
const RING_MAX: u16 = 1024;
/// Queue pairs used at most (each takes ring buffers from the heap).
const MAX_PAIRS: u16 = 4;
/// RX buffers per NIC, shared out over the queue pairs.
const RX_BUFFERS: u16 = 2048;
/// How long `send` waits for the device to free a TX slot before dropping.
const TX_WAIT_US: u64 = 50;

struct RxQ {
    q: Queue,
    /// by descriptor
    bufs: Vec<Buf>,
    kick: bool,
}

struct TxQ {
    q: Queue,
    /// buffers the device is sending, by descriptor
    inflight: Vec<Option<Buf>>,
    /// one per free descriptor, to hand out in exchange
    spare: Vec<Buf>,
    free: Vec<u16>,
    kick: u16,
}

impl TxQ {
    /// Take back what the device sent.
    fn reclaim(&mut self) {
        while let Some((id, _)) = self.q.pop() {
            if let Some(b) = self.inflight[id as usize].take() {
                // a big segment's buffer is not kept around
                self.spare.push(if b.len() > BUF_SIZE { new_buf() } else { b });
            }
            self.free.push(id);
        }
    }

    /// A free descriptor, waiting a little for one if the ring is full.
    fn slot(&mut self, stats: &mut devices::DevStats) -> Option<u16> {
        self.reclaim();
        if self.free.is_empty() {
            // full: make sure the device is draining it, and give it a moment
            // (dropping costs more than waiting while the CPU has time)
            self.q.notify();
            self.kick = 0;
            stats.tx_wait += 1;
            let until = crate::arch::rdtsc() + crate::arch::tsc_per_ms() * TX_WAIT_US / 1000;
            loop {
                self.reclaim();
                if !self.free.is_empty() {
                    break;
                }
                if crate::arch::rdtsc() > until {
                    stats.tx_full += 1;
                    return None;
                }
                core::hint::spin_loop();
            }
        }
        self.free.pop()
    }

    /// Queue descriptor `id` for `buf[at..at + len]` (header included).
    fn post(&mut self, id: u16, buf: Buf, at: usize, len: usize) {
        self.q.set_desc(id, buf.as_ptr() as u64 + at as u64, len as u32, 0, 0);
        self.inflight[id as usize] = Some(buf);
        self.q.push(id);
        self.kick += 1;
        if self.kick >= 32 {
            self.q.kick();
            self.kick = 0;
        }
    }
}

pub struct VirtioNet {
    dev: Virtio,
    rx: Vec<RxQ>,
    tx: Vec<TxQ>,
    /// control queue and its buffer
    ctrl: Option<(Queue, Vec<u8>)>,
    /// RX queue to look at first (round robin)
    next_rx: usize,
    hdr: usize,
    /// receive buffers come in several pieces (MRG_RXBUF)
    mrg: bool,
    /// the host completes checksums and cuts segments we send (CSUM, HOST_TSO4), with ECN
    tx_offload: bool,
    tx_ecn: bool,
    pub mac: [u8; 6],
    /// legacy interrupt routed (else the timer wakes us)
    pub irq: bool,
    stats: devices::DevStats,
}

pub fn is_net(d: &PciDev) -> bool {
    d.vendor == 0x1AF4 && (d.device == 0x1000 || d.device == 0x1041)
}

/// Give the device RX buffer `b` as descriptor `id`: the frame lands at
/// HEADROOM, its virtio header just before.
fn post_rx(q: &mut Queue, id: u16, b: &Buf, hdr: usize) {
    q.set_desc(id, b.as_ptr() as u64 + (HEADROOM - hdr) as u64, (BUF_SIZE - HEADROOM + hdr) as u32, D_WRITE, 0);
    q.push(id);
}

/// TX queue for a frame: by IPv4 addresses and ports, so a flow keeps one queue.
fn flow_hash(f: &[u8]) -> u32 {
    let mut o = 12;
    if f.len() >= 18 && f[12..14] == [0x81, 0x00] {
        o = 16;
    }
    let ip = o + 2;
    if f.len() < ip + 20 || f[o..ip] != [0x08, 0x00] {
        return 0;
    }
    let rd = |i: usize| u32::from_be_bytes([f[i], f[i + 1], f[i + 2], f[i + 3]]);
    let mut h = rd(ip + 12) ^ rd(ip + 16).rotate_left(16);
    let l4 = ip + (f[ip] & 15) as usize * 4;
    if matches!(f[ip + 9], 6 | 17) && f.len() >= l4 + 4 {
        h ^= rd(l4);
    }
    h ^= h >> 16;
    h = h.wrapping_mul(0x45d9_f3b);
    h ^ (h >> 16)
}

impl VirtioNet {
    pub fn new(pci: &PciDev, offloads: bool) -> Option<VirtioNet> {
        let dev = Virtio::probe(pci)?;
        let modern = dev.is_modern();
        let offered = dev.offered();
        let mut want = F_MAC | if modern { F_CTRL_VQ | F_CTRL_RX | F_MQ } else { 0 };
        if modern && offloads {
            // big segments in only with buffers that chain (MRG_RXBUF)
            if offered & F_MRG_RXBUF != 0 {
                want |= F_MRG_RXBUF | F_GUEST_CSUM | F_GUEST_TSO4 | F_GUEST_ECN;
            }
            want |= F_CSUM | F_HOST_TSO4 | F_HOST_ECN;
        }
        let mut feat = dev.begin(want)?;
        if feat & F_GUEST_TSO4 != 0 && feat & (F_MRG_RXBUF | F_GUEST_CSUM) != F_MRG_RXBUF | F_GUEST_CSUM {
            feat = dev.begin(want & !(F_GUEST_TSO4 | F_GUEST_ECN))?; // not without them
        }
        // virtio_net_hdr: 12 bytes with VERSION_1, 10 bytes for legacy
        let hdr = if modern { 12 } else { 10 };
        let max_pairs = if feat & F_MQ != 0 { dev.config16(8).max(1) } else { 1 };
        let pairs = max_pairs.min(MAX_PAIRS);
        // as large as the device allows: rings absorb bursts
        let ring = (RX_BUFFERS / pairs).min(RING_MAX);
        let mut rx = Vec::new();
        let mut tx = Vec::new();
        for p in 0..pairs {
            let mut q = dev.queue(2 * p, ring)?;
            let bufs: Vec<Buf> = (0..q.size).map(|_| new_buf()).collect();
            for (i, b) in bufs.iter().enumerate() {
                post_rx(&mut q, i as u16, b, hdr);
            }
            rx.push(RxQ { q, bufs, kick: false });
            let q = dev.queue(2 * p + 1, ring)?;
            let free = (0..q.size).collect();
            let spare = (0..q.size).map(|_| new_buf()).collect();
            tx.push(TxQ { inflight: (0..q.size).map(|_| None).collect(), q, spare, free, kick: 0 });
        }
        let ctrl = if feat & F_CTRL_VQ != 0 {
            let idx = if feat & F_MQ != 0 { 2 * max_pairs } else { 2 };
            dev.queue(idx, 16).map(|q| (q, vec![0u8; 64]))
        } else {
            None
        };
        let mut mac = [0u8; 6];
        if feat & F_MAC != 0 {
            for (i, b) in mac.iter_mut().enumerate() {
                *b = dev.config8(i);
            }
        } else {
            mac = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
        }
        dev.finish();
        for r in &rx {
            r.q.notify();
        }
        let tx_offload = feat & (F_CSUM | F_HOST_TSO4) == F_CSUM | F_HOST_TSO4;
        let mut n = VirtioNet {
            dev,
            rx,
            tx,
            ctrl,
            next_rx: 0,
            hdr,
            mrg: feat & F_MRG_RXBUF != 0,
            tx_offload,
            tx_ecn: feat & F_HOST_ECN != 0,
            mac,
            irq: false,
            stats: devices::DevStats::default(),
        };

        // more queue pairs: the device uses only the first until told
        if pairs > 1 && !n.ctrl(4, 0, &pairs.to_le_bytes()) {
            crate::kprintln!("net: the host refused {} queue pairs, using one", pairs);
            n.rx.truncate(1);
            n.tx.truncate(1);
        }
        // let the host drop unicast for other MACs (and multicast)
        let filtered = feat & F_CTRL_RX != 0 && n.ctrl(0, 0, &[0]) && n.ctrl(0, 1, &[0]);
        crate::kprintln!(
            "net: {} queue pair{} (rings rx {} tx {}), host MAC filter {}",
            n.rx.len(),
            if n.rx.len() == 1 { "" } else { "s" },
            n.rx[0].q.size,
            n.tx[0].q.size,
            if filtered { "on" } else { "off" }
        );
        n.describe_host();
        if offloads && modern {
            let on = |f: u64| feat & f == f;
            crate::kprintln!(
                "net: offloads: receive {}, send {}",
                if on(F_GUEST_TSO4 | F_MRG_RXBUF) { "big segments + partial checksums" } else if on(F_GUEST_CSUM) { "partial checksums" } else { "none" },
                if tx_offload { "big segments + partial checksums" } else { "none" }
            );
        }
        let line = pci.read8(0x3C);
        n.irq = n.dev.isr().is_some_and(|isr| crate::virtio::register_irq(line, isr));
        if n.irq {
            pci.enable_intx();
        } else {
            crate::kprintln!("net: no usable interrupt line ({}), the timer paces receiving", line);
        }
        Some(n)
    }

    /// What the host offers, for tuning (multiqueue, filtering, offloads).
    fn describe_host(&self) {
        let off = self.dev.offered();
        const NAMES: &[(u32, &str)] = &[
            (0, "csum"),
            (1, "guest_csum"),
            (7, "guest_tso4"),
            (11, "host_tso4"),
            (15, "mrg_rxbuf"),
            (17, "ctrl_vq"),
            (18, "ctrl_rx"),
            (19, "ctrl_vlan"),
            (22, "mq"),
            (23, "ctrl_mac_addr"),
            (28, "indirect_desc"),
            (29, "event_idx"),
            (32, "version_1"),
            (60, "rss"),
            (63, "speed_duplex"),
        ];
        let mut list = alloc::string::String::new();
        for &(bit, name) in NAMES {
            if off & (1 << bit) != 0 {
                list.push(' ');
                list.push_str(name);
            }
        }
        if off & F_MQ != 0 {
            list += &alloc::format!(" (max {} queue pairs)", self.dev.config16(8));
        }
        crate::kprintln!("net: host offers{}", list);
    }

    /// A control command; true if the device acknowledged it.
    fn ctrl(&mut self, class: u8, cmd: u8, data: &[u8]) -> bool {
        let Some((q, buf)) = self.ctrl.as_mut() else { return false };
        const ACK: usize = 48;
        buf[0] = class;
        buf[1] = cmd;
        buf[2..2 + data.len()].copy_from_slice(data);
        buf[ACK] = 0xFF;
        let a = buf.as_ptr() as u64;
        q.set_desc(0, a, (2 + data.len()) as u32, D_NEXT, 1);
        q.set_desc(1, a + ACK as u64, 1, D_WRITE, 0);
        q.push(0);
        q.notify();
        let until = crate::arch::rdtsc() + crate::arch::tsc_per_ms() * 100;
        while q.pop().is_none() {
            if crate::arch::rdtsc() > until {
                return false;
            }
            core::hint::spin_loop();
        }
        // Safety: the device wrote it; read it as memory that changed under us.
        unsafe { core::ptr::read_volatile(buf.as_ptr().add(ACK)) == 0 }
    }
}

impl devices::NetDevice for VirtioNet {
    fn mac(&self) -> [u8; 6] {
        self.mac
    }

    fn kind(&self) -> &'static str {
        if self.dev.is_modern() { "virtio-net (modern)" } else { "virtio-net (legacy)" }
    }

    fn send(&mut self, frame: &[u8]) -> bool {
        let n = self.tx.len();
        let len = frame.len().min(BUF_SIZE - HEADROOM);
        let t = &mut self.tx[if n > 1 { flow_hash(frame) as usize % n } else { 0 }];
        let Some(id) = t.slot(&mut self.stats) else { return false };
        // a copy into a spare buffer (frames built by the system's stack)
        let mut b = t.spare.pop().expect("one spare per free slot");
        b[HEADROOM - self.hdr..HEADROOM].fill(0);
        b[HEADROOM..HEADROOM + len].copy_from_slice(&frame[..len]);
        t.post(id, b, HEADROOM - self.hdr, self.hdr + len);
        self.stats.tx_pkts += 1;
        self.stats.tx_bytes += len as u64;
        true
    }

    fn send_swap(&mut self, buf: &mut Buf, start: usize, len: usize, off: Offload) -> bool {
        let tcp_cwr = |f: &[u8]| {
            let eth = if f.len() >= 18 && f[12..14] == [0x81, 0x00] { 18 } else { 14 };
            rustros_util::offload::csum_layout(f, eth).is_some_and(|(l4, _, _)| f.get(l4 as usize + 13).is_some_and(|fl| fl & 0x80 != 0))
        };
        // what the host cannot finish: done here
        if !off.is_none() && (!self.tx_offload || off.gso_size > 0 && !self.tx_ecn && tcp_cwr(&buf[start..start + len])) {
            return crate::offload::send_plain(self, &mut buf[start..start + len], off);
        }
        if start < self.hdr || start + len > buf.len() {
            return self.send(&buf[start..(start + len).min(buf.len())]); // no room for the header
        }
        let n = self.tx.len();
        let t = &mut self.tx[if n > 1 { flow_hash(&buf[start..start + len]) as usize % n } else { 0 }];
        let Some(id) = t.slot(&mut self.stats) else { return false };
        buf[start - self.hdr..start].fill(0);
        if !off.is_none() {
            let f = &buf[start..start + len];
            let eth = if f.len() >= 18 && f[12..14] == [0x81, 0x00] { 18 } else { 14 };
            if let Some((cstart, coff, hlen)) = rustros_util::offload::csum_layout(f, eth) {
                let cwr = off.gso_size > 0 && f[cstart as usize + 13] & 0x80 != 0;
                let h = &mut buf[start - self.hdr..start];
                h[0] = NEEDS_CSUM;
                if off.gso_size > 0 {
                    h[1] = GSO_TCPV4 | if cwr { GSO_ECN } else { 0 };
                    h[2..4].copy_from_slice(&hlen.to_le_bytes());
                    h[4..6].copy_from_slice(&off.gso_size.to_le_bytes());
                }
                h[6..8].copy_from_slice(&cstart.to_le_bytes());
                h[8..10].copy_from_slice(&coff.to_le_bytes());
            }
        }
        let frame = core::mem::replace(buf, t.spare.pop().expect("one spare per free slot"));
        t.post(id, frame, start - self.hdr, self.hdr + len);
        self.stats.tx_pkts += 1;
        self.stats.tx_bytes += len as u64;
        true
    }

    fn recv(&mut self, out: &mut [u8]) -> Option<usize> {
        let mut b = new_buf();
        let (n, off) = self.recv_swap(&mut b)?;
        let n = n.min(out.len());
        if off.csum_partial {
            rustros_util::offload::complete_csum(&mut b[HEADROOM..HEADROOM + n]);
        }
        out[..n].copy_from_slice(&b[HEADROOM..HEADROOM + n]);
        Some(n)
    }

    fn tx_offloads(&self) -> bool {
        self.tx_offload
    }

    fn stats(&self) -> devices::DevStats {
        self.stats
    }

    fn recv_swap(&mut self, buf: &mut Buf) -> Option<(usize, Offload)> {
        let n = self.rx.len();
        let hdr = self.hdr;
        for k in 0..n {
            let qi = (self.next_rx + k) % n;
            let r = &mut self.rx[qi];
            if r.q.used_count() == r.q.size {
                self.stats.rx_full += 1;
            }
            while let Some((id, len)) = r.q.pop() {
                let len = (len as usize).saturating_sub(hdr).min(BUF_SIZE - HEADROOM);
                let h = &r.bufs[id as usize][HEADROOM - hdr..HEADROOM];
                let pieces = if self.mrg { u16::from_le_bytes([h[10], h[11]]).max(1) } else { 1 };
                let gso = match h[1] & !GSO_ECN {
                    0 => Some(0),
                    GSO_TCPV4 => Some(u16::from_le_bytes([h[4], h[5]])),
                    _ => None, // not asked for
                };
                let off = Offload { csum_partial: h[0] & NEEDS_CSUM != 0, gso_size: gso.unwrap_or(0) };
                // a big segment over several buffers: put it together in one
                let big = if pieces > 1 {
                    let mut v = alloc::vec::Vec::with_capacity(HEADROOM + pieces as usize * (BUF_SIZE - HEADROOM));
                    v.resize(HEADROOM, 0);
                    v.extend_from_slice(&r.bufs[id as usize][HEADROOM..HEADROOM + len]);
                    post_rx(&mut r.q, id, &r.bufs[id as usize], hdr);
                    for _ in 1..pieces {
                        let Some((id2, len2)) = r.q.pop() else { break };
                        let len2 = (len2 as usize).min(BUF_SIZE - HEADROOM + hdr);
                        v.extend_from_slice(&r.bufs[id2 as usize][HEADROOM - hdr..HEADROOM - hdr + len2]);
                        post_rx(&mut r.q, id2, &r.bufs[id2 as usize], hdr);
                    }
                    r.kick = true;
                    Some(v)
                } else {
                    None
                };
                let d: &[u8] = match &big {
                    Some(v) => &v[HEADROOM..],
                    None => &r.bufs[id as usize][HEADROOM..HEADROOM + len],
                };
                let flen = d.len();
                // unicast for another MAC (flooded to us), or an offload we
                // did not ask for: straight back to the ring
                let foreign = flen >= 6 && d[0] & 1 == 0 && d[..6] != self.mac;
                if foreign || gso.is_none() {
                    if foreign {
                        self.stats.rx_foreign += 1;
                    }
                    if big.is_none() {
                        post_rx(&mut r.q, id, &r.bufs[id as usize], hdr);
                        r.kick = true;
                    }
                    continue;
                }
                match big {
                    Some(v) => *buf = v.into_boxed_slice(),
                    None => {
                        // the frame's buffer for the kernel's spare one (a
                        // small one: big ones are not kept in rings)
                        if buf.len() > BUF_SIZE {
                            *buf = new_buf();
                        }
                        let slot = &mut r.bufs[id as usize];
                        core::mem::swap(slot, buf);
                        post_rx(&mut r.q, id, slot, hdr);
                        r.kick = true;
                    }
                }
                self.stats.rx_pkts += 1;
                self.stats.rx_bytes += flen as u64;
                // next time start at the next queue: fair to all of them
                self.next_rx = (qi + 1) % n;
                return Some((flen, off));
            }
        }
        None
    }

    fn flush(&mut self) {
        for r in self.rx.iter_mut().filter(|r| r.kick) {
            r.q.kick();
            r.kick = false;
        }
        for t in self.tx.iter_mut().filter(|t| t.kick != 0) {
            t.q.kick();
            t.kick = 0;
        }
    }

    fn rx_pending(&self) -> bool {
        self.rx.iter().any(|r| r.q.has_used())
    }

    fn rx_interrupts(&mut self, on: bool) {
        if self.irq {
            for r in &self.rx {
                r.q.set_interrupts(on);
            }
        }
    }
}
