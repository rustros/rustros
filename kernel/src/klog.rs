//! Console output on its way to the log on disk (the storage service keeps
//! it, one ring per boot): buffered here until the main loop hands it over.

use alloc::vec::Vec;

use crate::Global;

/// Console output kept in RAM until it reaches the disk.
const PENDING_MAX: usize = 64 * 1024;

struct Pending {
    buf: Vec<u8>,
    lost: u64,
}

static PENDING: Global<Pending> = Global::new(Pending { buf: Vec::new(), lost: 0 });

/// Called for all console output.
pub fn append(s: &[u8]) {
    // Safety: single core; the console is the only writer.
    let p = unsafe { PENDING.get() };
    if p.buf.len() + s.len() > PENDING_MAX {
        p.lost += s.len() as u64;
        return;
    }
    p.buf.extend_from_slice(s);
}

/// Hand what was printed since the last time to the log on disk.
pub fn flush(s: &mut dyn rustros_api::module::Storage) {
    // Safety: single core; nothing prints while we take the buffer.
    let p = unsafe { PENDING.get() };
    if p.buf.is_empty() && p.lost == 0 {
        return;
    }
    let mut data = core::mem::take(&mut p.buf);
    if p.lost > 0 {
        data.extend_from_slice(alloc::format!("\n[log: {} bytes lost]\n", p.lost).as_bytes());
        p.lost = 0;
    }
    s.log_write(&data);
}
