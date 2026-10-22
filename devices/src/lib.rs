//! Device interfaces between the kernel's drivers and the system services.
//! Services are written against these traits only, so they can be tested on
//! the host with in-memory devices.
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

pub const SECTOR: usize = 512;

/// Free bytes in front of a received frame (headers to add; the same as
/// rustros_api::HEADROOM).
pub const HEADROOM: usize = 64;
/// A packet buffer: HEADROOM, then up to 2048 bytes of frame.
pub const BUF_SIZE: usize = HEADROOM + 2048;
/// Packet buffers are handed between the kernel and the drivers instead of
/// copying what is in them.
pub type Buf = alloc::boxed::Box<[u8; BUF_SIZE]>;

pub fn new_buf() -> Buf {
    alloc::boxed::Box::new([0u8; BUF_SIZE])
}

/// A disk addressed in 512-byte sectors.
pub trait BlockDevice {
    /// Read `buf.len()` bytes (a multiple of 512) starting at sector `lba`.
    fn read(&mut self, lba: u64, buf: &mut [u8]) -> bool;
    /// Write `buf.len()` bytes (a multiple of 512) starting at sector `lba`;
    /// durable when it returns true.
    fn write(&mut self, lba: u64, buf: &[u8]) -> bool;
    fn sectors(&self) -> u64;
    fn read_only(&self) -> bool {
        false
    }
}

/// Counters of a NIC, kept by its driver (all traffic, forwarded too).
#[derive(Clone, Copy, Default, Debug)]
pub struct DevStats {
    pub rx_pkts: u64,
    pub rx_bytes: u64,
    pub tx_pkts: u64,
    pub tx_bytes: u64,
    /// frames not sent: the TX ring stayed full
    pub tx_full: u64,
    /// times the TX ring was full and the driver waited for room
    pub tx_wait: u64,
    /// times the RX ring was found completely full (the host drops then)
    pub rx_full: u64,
    /// unicast frames for other MACs, dropped on arrival
    pub rx_foreign: u64,
}

/// An Ethernet interface.
pub trait NetDevice {
    fn stats(&self) -> DevStats {
        DevStats::default()
    }
    fn mac(&self) -> [u8; 6];
    /// Transmit one frame (without FCS). False if the device is busy.
    fn send(&mut self, frame: &[u8]) -> bool;
    /// Copy the next received frame into `buf`; returns its length.
    fn recv(&mut self, buf: &mut [u8]) -> Option<usize>;
    /// Short description for the boot log.
    fn kind(&self) -> &'static str;
    /// Zero-copy receive: the next frame ends up in `buf` (at HEADROOM; the
    /// length is returned) and the driver keeps the buffer that was there.
    fn recv_swap(&mut self, buf: &mut Buf) -> Option<usize> {
        self.recv(&mut buf[HEADROOM..])
    }
    /// Zero-copy send of `buf[start..start + len]`: the driver keeps the
    /// buffer until the device is done with it and leaves a spare one in
    /// `buf`. False if the device is busy (`buf` is then unchanged).
    fn send_swap(&mut self, buf: &mut Buf, start: usize, len: usize) -> bool {
        self.send(&buf[start..start + len])
    }
    /// Tell the device about frames sent and buffers returned since the last
    /// flush (`send`/`recv` batch their notifications, which are expensive
    /// under a hypervisor). Call after each batch.
    fn flush(&mut self) {}
    /// A received frame is waiting.
    fn rx_pending(&self) -> bool {
        false
    }
    /// Interrupt on received frames (before sleeping) or not (while polling).
    fn rx_interrupts(&mut self, _on: bool) {}
}
