//! Zero-copy packet path for forwarding apps (NAT, routing, tunnels).
//!
//! The kernel receives a batch of frames into buffers with `HEADROOM` free
//! bytes in front and hands the batch to each packet app in turn
//! (`Module::on_frames`). An app may rewrite a frame in place, add or strip
//! headers (`push_front` / `pull_front`) and decide its fate by setting
//! `verdict`; frames still `Pass` go on to the next app and finally to the
//! system's own stack. `Transmit` frames are sent out as they are, in one
//! batch. Nothing is allocated or copied on this path.

/// Free bytes in front of every received frame (enough for IPv4 + UDP +
/// L2TP + PPP encapsulation).
pub const HEADROOM: usize = 64;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Verdict {
    /// Not mine: continue to the next app, then the system stack.
    Pass,
    /// Discard.
    Drop,
    /// Handled (e.g. copied elsewhere); nothing more to do.
    Consumed,
    /// Send the (rewritten) frame out of the interface.
    Transmit,
}

pub struct Frame<'a> {
    buf: &'a mut [u8],
    start: usize,
    end: usize,
    pub verdict: Verdict,
    /// The NIC it arrived on; `Transmit` sends it out of this NIC, so a
    /// forwarding app sets it to the outgoing one.
    pub nic: u8,
    /// The kernel's buffer number (leave it alone).
    #[doc(hidden)]
    pub slot: u8,
}

impl<'a> Frame<'a> {
    /// A frame of `len` bytes at `buf[start..]`.
    pub fn new(buf: &'a mut [u8], start: usize, len: usize) -> Frame<'a> {
        let end = (start + len).min(buf.len());
        Frame { buf, start: start.min(end), end, verdict: Verdict::Pass, nic: 0, slot: 0 }
    }

    pub fn data(&self) -> &[u8] {
        &self.buf[self.start..self.end]
    }

    pub fn data_mut(&mut self) -> &mut [u8] {
        &mut self.buf[self.start..self.end]
    }

    pub fn len(&self) -> usize {
        self.end - self.start
    }

    pub fn is_empty(&self) -> bool {
        self.start == self.end
    }

    pub fn headroom(&self) -> usize {
        self.start
    }

    /// Grow the frame by `n` bytes at the front (encapsulation) and return
    /// them for the new header; None if the headroom is too small.
    pub fn push_front(&mut self, n: usize) -> Option<&mut [u8]> {
        let start = self.start.checked_sub(n)?;
        self.start = start;
        Some(&mut self.buf[start..start + n])
    }

    /// Strip `n` bytes from the front (decapsulation).
    pub fn pull_front(&mut self, n: usize) -> bool {
        if n > self.len() {
            return false;
        }
        self.start += n;
        true
    }

    /// Replace the frame's contents, keeping up to HEADROOM bytes in front.
    pub fn set_data(&mut self, data: &[u8]) -> bool {
        if data.len() > self.buf.len() {
            return false;
        }
        self.start = HEADROOM.min(self.buf.len() - data.len());
        self.end = self.start + data.len();
        self.buf[self.start..self.end].copy_from_slice(data);
        true
    }

    /// Shrink or grow (within the buffer) the frame's tail.
    pub fn set_len(&mut self, len: usize) -> bool {
        if self.start + len > self.buf.len() {
            return false;
        }
        self.end = self.start + len;
        true
    }
}
