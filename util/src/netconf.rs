//! The network configuration as stored: the kernel command line (GRUB puts
//! NIC 0's address there, from grubenv's net_ip/net_gw/net_mtu) and grubenv,
//! which `net save` writes.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use rustros_api::{IfConf, NetConf, RouteConf};
use crate::wire::{IpFmt, cmdline_get, fmt_ip_list, parse_cidr, parse_ip, parse_ip_list};

/// The configuration to boot with for `nics` NICs: NIC 0's address from
/// the command line (`ip=`, `gw=`, `mtu=`), the rest from the command line
/// (`extra=`, `ip1=`, `gw1=`, `mtu1=`, `extra1=`, ..., `vlans=`, `routes=`)
/// or else from grubenv (`net_extra`, `net1_ip`, ..., `net_vlans`,
/// `net_routes`). Also the lines for the boot log.
#[inline(never)]
pub fn from_boot(nics: usize, cmdline: &str, env: &dyn Fn(&str) -> Option<String>) -> (NetConf, Vec<String>) {
    let mut log = Vec::new();
    // the interfaces: the NICs, then the VLANs
    let mut ifs: Vec<IfConf> = (0..nics).map(|phys| IfConf { phys: phys as u8, mtu: 1500, ..IfConf::default() }).collect();
    let (ip, mask) = cmdline_get(cmdline, "ip").and_then(parse_cidr).unwrap_or((0, 0));
    let gw = cmdline_get(cmdline, "gw").and_then(parse_ip).unwrap_or(0);
    if ip == 0 {
        log.push(String::from("net: no ip= on the command line, address unconfigured"));
    } else {
        log.push(format!("net: ip {} gw {}", IpFmt(ip), IpFmt(gw)));
    }
    if let Some(f) = ifs.first_mut() {
        (f.ip, f.mask, f.gw) = (ip, mask, gw);
        if let Some(mtu) = cmdline_get(cmdline, "mtu").and_then(|m| m.parse::<usize>().ok()) {
            f.mtu = mtu.clamp(576, 1500) as u16;
            log.push(format!("net: mtu {}", f.mtu));
        }
    }
    // VLAN interfaces: "vlans=0.109,1.20"
    let vlans = cmdline_get(cmdline, "vlans").map(String::from).or_else(|| env("net_vlans"));
    for v in vlans.as_deref().unwrap_or("").split(',').filter(|s| !s.is_empty()) {
        let parsed = v.split_once('.').and_then(|(p, id)| Some((p.parse::<usize>().ok()?, id.parse::<u16>().ok()?)));
        match parsed {
            Some((phys, vid)) if phys < nics && (1..=4094).contains(&vid) && !ifs.iter().any(|f| f.phys as usize == phys && f.vlan == Some(vid)) => {
                ifs.push(IfConf { phys: phys as u8, vlan: Some(vid), mtu: 1500, ..IfConf::default() });
                log.push(format!("net: nic{} is VLAN {} on nic{}", ifs.len() - 1, vid, phys));
            }
            _ => log.push(format!("net: bad VLAN '{}' (want <nic>.<id>)", v)),
        }
    }
    for (nic, f) in ifs.iter_mut().enumerate() {
        let (c, e) = if nic == 0 { (String::new(), String::from("net_")) } else { (format!("{nic}"), format!("net{nic}_")) };
        let get = |k: &str| -> Option<String> { cmdline_get(cmdline, &format!("{k}{c}")).map(String::from).or_else(|| env(&format!("{e}{k}"))) };
        if nic > 0 {
            if let Some((ip, mask)) = get("ip").as_deref().and_then(parse_cidr) {
                f.ip = ip;
                f.mask = mask;
                f.gw = get("gw").as_deref().and_then(parse_ip).unwrap_or(0);
            }
            if let Some(mtu) = get("mtu").and_then(|m| m.parse::<usize>().ok()) {
                f.mtu = mtu.clamp(576, 1500) as u16;
            }
        }
        if let Some(list) = get("extra") {
            f.extra = parse_ip_list(&list).unwrap_or_default();
            f.extra.retain(|&a| a != 0 && a != f.ip);
        }
        if nic > 0 && f.ip != 0 {
            log.push(format!("net: nic{} ip {}/{}{}", nic, IpFmt(f.ip), f.mask.count_ones(), if f.gw != 0 { format!(" gw {}", IpFmt(f.gw)) } else { String::new() }));
        }
        if !f.extra.is_empty() {
            log.push(format!("net: nic{} {} extra addresses {}", nic, f.extra.len(), fmt_ip_list(&f.extra)));
        }
    }
    // static routes: "routes=10.9.0.0/16>10.20.0.1,0.0.0.0/0>gw<10.20.0.1/32,..."
    let routes = cmdline_get(cmdline, "routes").map(String::from).or_else(|| env("net_routes"));
    let mut rts = Vec::new();
    for r in routes.as_deref().unwrap_or("").split(',').filter(|s| !s.is_empty()) {
        match parse_route(r) {
            Some(rt) => {
                log.push(format!("net: route {}", fmt_route(&rt).replace('>', " via ").replace('<', " from ")));
                rts.push(rt);
            }
            None => log.push(format!("net: bad route '{}' (want a.b.c.d/n>gateway[<source/n])", r)),
        }
    }
    (NetConf { ifs, routes: rts }, log)
}

/// The grubenv variables that make `conf` the boot configuration: NIC 0 as
/// net_ip/net_gw/net_mtu (GRUB passes those on the command line), the rest
/// as net<n>_*, net_vlans and net_routes; those of interfaces that are gone
/// are cleared.
#[inline(never)]
pub fn to_env(conf: &NetConf) -> Vec<(String, String)> {
    let mut vars: Vec<(String, String)> = Vec::new();
    let vlans: Vec<String> = conf.ifs.iter().filter_map(|f| f.vlan.map(|v| format!("{}.{}", f.phys, v))).collect();
    vars.push((String::from("net_vlans"), vlans.join(",")));
    let routes: Vec<String> = conf.routes.iter().map(fmt_route).collect();
    vars.push((String::from("net_routes"), routes.join(",")));
    for i in conf.ifs.len()..16 {
        for k in ["ip", "gw", "mtu", "extra"] {
            vars.push((format!("net{i}_{k}"), String::new()));
        }
    }
    for (i, f) in conf.ifs.iter().enumerate() {
        let p = if i == 0 { String::from("net_") } else { format!("net{i}_") };
        let set = f.ip != 0;
        vars.push((format!("{p}ip"), if set { format!("{}/{}", IpFmt(f.ip), f.mask.count_ones()) } else { String::new() }));
        vars.push((format!("{p}gw"), if set && f.gw != 0 { format!("{}", IpFmt(f.gw)) } else { String::new() }));
        vars.push((format!("{p}mtu"), if f.mtu == 1500 { String::new() } else { format!("{}", f.mtu) }));
        vars.push((format!("{p}extra"), fmt_ip_list(&f.extra)));
    }
    vars
}

/// A route as stored: "net/n>gw" or "net/n>gw<src/n".
fn parse_route(r: &str) -> Option<RouteConf> {
    let (r, src) = match r.split_once('<') {
        Some((r, s)) => (r, Some(parse_cidr(s)?)),
        None => (r, None),
    };
    let (n, g) = r.split_once('>')?;
    let ((net, mask), gw) = (parse_cidr(n)?, parse_ip(g)?);
    let (src, src_mask) = src.unwrap_or((0, 0));
    (net & !mask == 0 && src & !src_mask == 0 && gw != 0).then_some(RouteConf { net, mask, gw, src, src_mask })
}

fn fmt_route(r: &RouteConf) -> String {
    let mut s = format!("{}/{}>{}", IpFmt(r.net), r.mask.count_ones(), IpFmt(r.gw));
    if r.src_mask != 0 {
        s += &format!("<{}/{}", IpFmt(r.src), r.src_mask.count_ones());
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let cmd = "ip=10.0.2.15/24 gw=10.0.2.2 mtu=1400 vlans=0.109,1.20,0.109 routes=10.9.0.0/16>10.0.2.1,0.0.0.0/0>10.0.2.3<10.0.2.15/32 ip2=10.20.0.2/24";
        let env = |k: &str| match k {
            "net1_ip" => Some(String::from("192.168.1.1/24")),
            "net_extra" => Some(String::from("10.0.2.16-10.0.2.17")),
            _ => None,
        };
        let (c, log) = from_boot(2, cmd, &env);
        assert_eq!(c.ifs.len(), 4);
        assert_eq!((c.ifs[0].mtu, c.ifs[0].extra.len()), (1400, 2));
        assert_eq!((c.ifs[2].phys, c.ifs[2].vlan, c.ifs[2].ip), (0, Some(109), 0x0a140002));
        assert_eq!(c.ifs[1].ip, 0xc0a80101);
        assert_eq!(c.routes.len(), 2);
        assert!(log.iter().any(|l| l == "net: bad VLAN '0.109' (want <nic>.<id>)"));
        // what is saved comes back from grubenv alone (NIC 0's address via GRUB)
        let vars = to_env(&c);
        let get = |k: &str| vars.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone()).filter(|v| !v.is_empty());
        let cmd0 = format!("ip={} gw={} mtu={}", get("net_ip").unwrap(), get("net_gw").unwrap(), get("net_mtu").unwrap());
        assert_eq!(from_boot(2, &cmd0, &get).0, c);
    }
}
