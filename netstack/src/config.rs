//! The configuration of the interfaces and routes, as a whole: what is in
//! effect, the candidate being edited, and the apply / confirm / revert
//! round (an applied candidate that is not confirmed in time is reverted).

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use rustros_api::{IfConf, NetConf, RouteConf};
use rustros_util::wire::IpFmt;

use crate::iface::{Iface, Route};
use crate::stack::Stack;

#[derive(Default)]
pub struct Config {
    /// The NICs' MACs (interface `i < macs.len()` is NIC `i`).
    pub macs: Vec<[u8; 6]>,
    /// What each interface is: (NIC, VLAN).
    links: Vec<(u8, Option<u16>)>,
    candidate: Option<NetConf>,
    /// What ran before the first apply (the revert point).
    baseline: Option<NetConf>,
    /// When an applied candidate is reverted unless confirmed.
    deadline: Option<u64>,
}

impl Stack {
    pub fn running(&self) -> NetConf {
        let ifs = self
            .ifs
            .0
            .iter()
            .zip(&self.conf.links)
            .map(|(f, &(phys, vlan))| IfConf { phys, vlan, ip: f.ip, mask: f.mask, gw: f.gw, mtu: f.mtu as u16, extra: f.extra.clone() })
            .collect();
        let routes = self.ifs.1.iter().map(|r| RouteConf { net: r.net, mask: r.mask, gw: r.gw, src: r.src, src_mask: r.src_mask }).collect();
        NetConf { ifs, routes }
    }

    /// Put a whole configuration in effect: the NICs keep their interfaces
    /// (and ARP caches unless their address changes), VLAN interfaces come
    /// and go as listed.
    #[inline(never)]
    pub fn set_config(&mut self, net: &NetConf) -> Result<(), String> {
        for r in &net.routes {
            if r.net & !r.mask != 0 || r.src & !r.src_mask != 0 || r.gw == 0 {
                return Err(format!("bad route {}/{}", IpFmt(r.net), r.mask.count_ones()));
            }
        }
        let nics = self.conf.macs.len();
        let mut map: Vec<(u8, Option<u16>)> = (0..nics).map(|phys| (phys as u8, None)).collect();
        let mut by_map: Vec<Option<&IfConf>> = alloc::vec![None; nics];
        for c in &net.ifs {
            if c.phys as usize >= nics {
                return Err(format!("no nic{}", c.phys));
            }
            match c.vlan {
                None => by_map[c.phys as usize] = Some(c),
                Some(v) if (1..=4094).contains(&v) && !map.contains(&(c.phys, c.vlan)) => {
                    map.push((c.phys, c.vlan));
                    by_map.push(Some(c));
                }
                Some(_) => return Err(format!("bad or repeated VLAN {}", c.name())),
            }
        }
        // interfaces that stay keep what they have (their ARP cache too)
        let mut old: Vec<Option<Iface>> = core::mem::take(&mut self.ifs.0).into_iter().map(Some).collect();
        for (i, m) in map.iter().enumerate() {
            let was = self.conf.links.iter().position(|o| o == m);
            let mut f = was.and_then(|w| old.get_mut(w)?.take()).unwrap_or_else(|| Iface::new(i, self.conf.macs[m.0 as usize], 0, 0, 0));
            if let Some(c) = by_map[i] {
                let mut extra: Vec<u32> = c.extra.iter().copied().filter(|&a| a != 0 && a != c.ip).collect();
                rustros_util::sort::sort(&mut extra);
                extra.dedup();
                if (f.ip, f.mask, f.gw) != (c.ip, c.mask, c.gw) {
                    f.arp.clear();
                }
                (f.ip, f.mask, f.gw, f.mtu, f.extra) = (c.ip, c.mask, c.gw, c.mtu.clamp(576, 1500) as usize, extra);
            }
            f.nic = i;
            self.ifs.0.push(f);
        }
        self.conf.links = map;
        self.ifs.1 = net.routes.iter().map(|r| Route { net: r.net, mask: r.mask, gw: r.gw, src: r.src, src_mask: r.src_mask }).collect();
        Ok(())
    }

    pub fn candidate(&self) -> Option<NetConf> {
        self.conf.candidate.clone()
    }

    pub fn set_candidate(&mut self, conf: Option<NetConf>) {
        self.conf.candidate = conf;
    }

    pub fn apply(&mut self, now: u64, seconds: u32) -> Result<(), String> {
        let cand = self.conf.candidate.clone().ok_or_else(|| String::from("no candidate configuration"))?;
        let before = self.running();
        self.set_config(&cand)?;
        if self.conf.baseline.is_none() {
            self.conf.baseline = Some(before);
        }
        self.conf.deadline = (seconds > 0).then(|| now + seconds as u64 * 1000);
        Ok(())
    }

    /// Back to the revert point (the candidate and the revert point stay).
    pub fn revert(&mut self) -> Result<bool, String> {
        self.conf.deadline = None;
        let Some(base) = self.conf.baseline.clone() else { return Ok(false) };
        self.set_config(&base).map(|()| true)
    }

    pub fn confirm(&mut self) -> bool {
        self.conf.deadline.take().is_some()
    }

    pub fn discard(&mut self) {
        let _ = self.revert();
        self.conf.baseline = None;
        self.conf.candidate = None;
    }

    pub fn pending(&self, now: u64) -> Option<u64> {
        self.conf.deadline.map(|t| t.saturating_sub(now) / 1000)
    }

    pub fn applied(&self) -> bool {
        self.conf.baseline.as_ref().is_some_and(|b| *b != self.running())
    }

    pub fn tick(&mut self, now: u64) -> Option<String> {
        if !self.conf.deadline.is_some_and(|t| now >= t) {
            return None;
        }
        Some(match self.revert() {
            Ok(_) => String::from("net: apply not confirmed in time, previous configuration restored (the candidate is kept)"),
            Err(e) => format!("net: revert failed: {e}"),
        })
    }

    /// The grubenv variables for `net save`; saving what runs ends the
    /// apply/revert round.
    pub fn save(&mut self) -> Vec<(String, String)> {
        self.conf.baseline = None;
        self.conf.deadline = None;
        self.conf.candidate = None;
        rustros_util::netconf::to_env(&self.running())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conf(ip: u32, vlan_ip: u32) -> NetConf {
        let nic = |phys, vlan, ip| IfConf { phys, vlan, ip, mask: 0xffffff00, gw: 0, mtu: 1500, extra: Vec::new() };
        NetConf { ifs: alloc::vec![nic(0, None, ip), nic(1, None, 0), nic(1, Some(20), vlan_ip)], routes: Vec::new() }
    }

    #[test]
    fn apply_revert() {
        let mut s = Stack::new([0; 6], 0, 0, 0);
        s.conf.macs = alloc::vec![[2; 6], [3; 6]];
        let a = conf(0x0a000001, 0x0a140001);
        s.set_config(&a).unwrap();
        assert_eq!(s.running(), a);
        assert_eq!(s.ifs.0[2].mac, [3; 6]);
        assert!(s.set_config(&NetConf { ifs: alloc::vec![IfConf { phys: 2, ..IfConf::default() }], routes: Vec::new() }).is_err());
        // a candidate applied with a deadline, reverted when it passes
        let b = conf(0x0a000002, 0x0a140002);
        s.set_candidate(Some(b.clone()));
        s.apply(1000, 10).unwrap();
        assert_eq!(s.running(), b);
        assert!(s.applied());
        assert_eq!(s.pending(5000), Some(6));
        assert!(s.tick(5000).is_none());
        assert!(s.tick(11000).is_some());
        assert_eq!(s.running(), a);
        assert_eq!(s.candidate(), Some(b));
        s.discard();
        assert_eq!((s.candidate(), s.applied()), (None, false));
    }
}
