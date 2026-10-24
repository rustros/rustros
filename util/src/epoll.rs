//! An epoll instance over any waitable objects (sockets today; pipes, Unix
//! sockets and timers of the process layer later), with Linux's semantics:
//! level-triggered entries are reported while their object stays ready,
//! edge-triggered ones (`EPOLLET`) once per reported event, `EPOLLONESHOT`
//! ones once until re-armed with `EPOLL_CTL_MOD`.
//!
//! Events are pushed in by whoever owns the objects (`event`), at the moment
//! of the change; `wait` takes the ready list. An event that comes in before
//! anyone waits stays on the list, so a waiter that checks the list (under
//! the same lock as `event`, once there are several CPUs) cannot miss it.

use alloc::collections::VecDeque;
use alloc::vec::Vec;

use rustros_api::socket::{EPOLL_CTL_ADD, EPOLL_CTL_DEL, EPOLL_CTL_MOD, EPOLLERR, EPOLLET, EPOLLEXCLUSIVE, EPOLLHUP, EPOLLONESHOT, EpollEvent, Errno, SockResult};

/// Flags that change how an entry behaves; the rest are readiness bits.
const MODES: u32 = EPOLLET | EPOLLONESHOT | EPOLLEXCLUSIVE;

struct Item {
    obj: u64,
    events: u32,
    data: u64,
    /// on the ready list
    queued: bool,
    /// off after a one-shot report, until EPOLL_CTL_MOD
    armed: bool,
}

impl Item {
    /// The readiness bits it watches (errors and hang-ups always).
    fn interest(&self) -> u32 {
        (self.events & !MODES) | EPOLLERR | EPOLLHUP
    }
}

#[derive(Default)]
pub struct EpollSet {
    items: Vec<Item>,
    ready: VecDeque<u64>,
}

impl EpollSet {
    pub fn new() -> EpollSet {
        EpollSet::default()
    }

    fn find(&mut self, obj: u64) -> Option<&mut Item> {
        self.items.iter_mut().find(|i| i.obj == obj)
    }

    fn enqueue(&mut self, obj: u64) {
        if let Some(i) = self.find(obj) {
            if !i.queued && i.armed {
                i.queued = true;
                self.ready.push_back(obj);
            }
        }
    }

    /// EPOLL_CTL_ADD / MOD / DEL; `now` is the object's readiness at this
    /// moment (an object that is ready already gets reported).
    pub fn ctl(&mut self, op: i32, obj: u64, events: u32, data: u64, now: u32) -> SockResult<()> {
        match op {
            EPOLL_CTL_ADD => {
                if self.find(obj).is_some() {
                    return Err(Errno::EEXIST);
                }
                self.items.push(Item { obj, events, data, queued: false, armed: true });
            }
            EPOLL_CTL_MOD => {
                let i = self.find(obj).ok_or(Errno::ENOENT)?;
                if events & EPOLLEXCLUSIVE != 0 || i.events & EPOLLEXCLUSIVE != 0 {
                    return Err(Errno::EINVAL);
                }
                (i.events, i.data, i.armed) = (events, data, true);
            }
            EPOLL_CTL_DEL => {
                let n = self.items.len();
                self.forget(obj);
                return if self.items.len() < n { Ok(()) } else { Err(Errno::ENOENT) };
            }
            _ => return Err(Errno::EINVAL),
        }
        let watched = self.find(obj).map_or(0, |i| i.interest());
        if now & watched != 0 {
            self.enqueue(obj);
        }
        Ok(())
    }

    /// `obj` changed: `events` say what happened.
    pub fn event(&mut self, obj: u64, events: u32) {
        let Some(i) = self.find(obj) else { return };
        if events & i.interest() != 0 {
            self.enqueue(obj);
        }
    }

    /// The object is gone (closed): no longer watched.
    pub fn forget(&mut self, obj: u64) {
        self.items.retain(|i| i.obj != obj);
        self.ready.retain(|&o| o != obj);
    }

    /// Whether anything is on the ready list (it may turn out not ready).
    pub fn pending(&self) -> bool {
        !self.ready.is_empty()
    }

    /// For the state handover (`snap`).
    pub fn save(&self, w: &mut crate::snap::W) {
        w.n(self.items.len());
        for i in &self.items {
            w.u64(i.obj);
            w.u32(i.events);
            w.u64(i.data);
            w.u8(i.queued as u8 | (i.armed as u8) << 1);
        }
        w.n(self.ready.len());
        for &o in &self.ready {
            w.u64(o);
        }
    }

    pub fn load(r: &mut crate::snap::R) -> Result<EpollSet, crate::snap::Bad> {
        let items = r.list(|r| {
            let (obj, events, data, f) = (r.u64()?, r.u32()?, r.u64()?, r.u8()?);
            Ok(Item { obj, events, data, queued: f & 1 != 0, armed: f & 2 != 0 })
        })?;
        Ok(EpollSet { items, ready: r.list(|r| r.u64())?.into() })
    }

    /// Ready entries into `out`, each with the object's readiness now
    /// (`ready_now`; None: the object is gone). Never waits.
    pub fn wait(&mut self, out: &mut [EpollEvent], mut ready_now: impl FnMut(u64) -> Option<u32>) -> usize {
        let mut n = 0;
        // each entry looked at once per call: level-triggered ones go back
        // to the end of the list
        let mut left = self.ready.len();
        while n < out.len() && left > 0 {
            left -= 1;
            let Some(obj) = self.ready.pop_front() else { break };
            let Some(now) = ready_now(obj) else {
                self.forget(obj);
                continue;
            };
            let Some(i) = self.find(obj) else { continue };
            i.queued = false;
            let rev = now & i.interest();
            if rev == 0 || !i.armed {
                continue;
            }
            out[n] = EpollEvent { events: rev, data: i.data };
            n += 1;
            if i.events & EPOLLONESHOT != 0 {
                i.armed = false;
            } else if i.events & EPOLLET == 0 {
                i.queued = true;
                self.ready.push_back(obj);
            }
        }
        n
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustros_api::socket::{EPOLLIN, EPOLLOUT};

    fn wait(e: &mut EpollSet, now: u32) -> Vec<EpollEvent> {
        let mut out = [EpollEvent::default(); 8];
        let n = e.wait(&mut out, |_| Some(now));
        out[..n].to_vec()
    }

    #[test]
    fn level_edge_oneshot() {
        // level: reported while ready
        let mut e = EpollSet::new();
        e.ctl(EPOLL_CTL_ADD, 1, EPOLLIN, 10, 0).unwrap();
        assert!(wait(&mut e, EPOLLIN).is_empty());
        e.event(1, EPOLLIN);
        assert_eq!(wait(&mut e, EPOLLIN), [EpollEvent { events: EPOLLIN, data: 10 }]);
        assert_eq!(wait(&mut e, EPOLLIN).len(), 1);
        assert!(wait(&mut e, 0).is_empty());
        assert!(wait(&mut e, EPOLLIN).is_empty());
        // an event for something not watched does nothing
        e.event(1, EPOLLOUT);
        assert!(!e.pending());
        // edge: once per event, again on the next one
        let mut e = EpollSet::new();
        e.ctl(EPOLL_CTL_ADD, 2, EPOLLIN | EPOLLET, 20, 0).unwrap();
        e.event(2, EPOLLIN);
        assert_eq!(wait(&mut e, EPOLLIN).len(), 1);
        assert!(wait(&mut e, EPOLLIN).is_empty());
        e.event(2, EPOLLIN);
        assert_eq!(wait(&mut e, EPOLLIN).len(), 1);
        // added while ready: reported at once; errors always
        let mut e = EpollSet::new();
        e.ctl(EPOLL_CTL_ADD, 3, EPOLLIN | EPOLLONESHOT, 30, EPOLLIN).unwrap();
        assert_eq!(wait(&mut e, EPOLLIN | EPOLLERR), [EpollEvent { events: EPOLLIN | EPOLLERR, data: 30 }]);
        e.event(3, EPOLLIN);
        assert!(wait(&mut e, EPOLLIN).is_empty());
        e.ctl(EPOLL_CTL_MOD, 3, EPOLLIN, 31, EPOLLIN).unwrap();
        assert_eq!(wait(&mut e, EPOLLIN)[0].data, 31);
        assert_eq!(e.ctl(EPOLL_CTL_ADD, 3, EPOLLIN, 0, 0), Err(Errno::EEXIST));
        e.ctl(EPOLL_CTL_DEL, 3, 0, 0, 0).unwrap();
        assert_eq!(e.ctl(EPOLL_CTL_DEL, 3, 0, 0, 0), Err(Errno::ENOENT));
        assert!(wait(&mut e, EPOLLIN).is_empty());
    }
}
