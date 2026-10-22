//! Network commands, shared by the rescue console, the shell and the
//! updater's remote `net` command. Three stages, as on a router:
//!
//! ```text
//! ip / mtu ...          change the running configuration right away
//! cand ip / cand mtu .. change the candidate only (neither in effect nor stored)
//! cand                  show the candidate and how it differs
//! apply [seconds]       candidate -> running, then asks whether to keep it
//!                       (as iptables-apply): reverted unless confirmed within
//!                       `seconds` (default 10, 0: no limit)
//! revert                back to what ran before; apply again at will
//! confirm               stop the revert timer
//! discard               revert if applied, drop the candidate
//! save                  running -> stored for the next boots; ends the round
//! ```
//!
//! `ip` arguments:
//!
//! ```text
//! [nicN] a.b.c.d/n [gateway]    set an address (nic0 if not named)
//! [nicN] none                   remove it
//! [nicN] add|del <list>         extra addresses (NAT egress); a list is
//!                               a.b.c.d[-a.b.c.e | -e][,...]
//! vlan add nicN <id>            VLAN interface nicN.<id>
//! vlan del nicN.<id>
//! route add a.b.c.d/n <gw> [from s.s.s.s[/n]]
//!                               static route (gateway on a connected
//!                               network), for one source only with `from`
//!                               (several WANs: which hosts leave by which)
//! route del a.b.c.d/n [from s.s.s.s[/n]]
//! ```

use alloc::string::String;
use alloc::vec::Vec;

use rustros_api::{IfConf, NetConf, RouteConf, Sys};

use crate::wire::{IpFmt, MacFmt, fmt_ip_list, parse_cidr, parse_ip, parse_ip_list};

/// How long an apply waits for its confirmation (iptables-apply's default).
pub const DEFAULT_APPLY_SECONDS: u32 = 10;

pub const USAGE: &str = "usage: [cand] ip [nicN] a.b.c.d/n [gw] | none | add|del a.b.c.d[-e][,...] | vlan add|del ... | route add a.b.c.d/n gw [from a.b.c.d[/n]] | route del a.b.c.d/n [from ...]\n       [cand] mtu [nicN] <n> | cand | apply [seconds] | revert | confirm | discard | save\n";

/// Interface index by name ("nic0", "nic0.109").
pub fn find_nic(sys: &mut dyn Sys, name: &str) -> Option<usize> {
    let net = sys.net()?;
    (0..net.nic_count()).find(|&i| net.nic_name(i) == name)
}

/// A configuration, one interface per line (extra addresses on the next).
pub fn fmt_conf(net: &NetConf) -> String {
    let mut out = String::new();
    for c in &net.ifs {
        let addr = if c.ip == 0 { String::from("none") } else { alloc::format!("{}/{}", IpFmt(c.ip), c.mask.count_ones()) };
        out += &alloc::format!("{} ip {}  gw {}  mtu {}\n", c.name(), addr, IpFmt(c.gw), c.mtu);
        if !c.extra.is_empty() {
            out += &alloc::format!("{} extra ({}) {}\n", c.name(), c.extra.len(), fmt_ip_list(&c.extra));
        }
    }
    out += &fmt_routes(&net.routes);
    out
}

fn fmt_routes(routes: &[RouteConf]) -> String {
    routes
        .iter()
        .map(|r| {
            let from = if r.src_mask != 0 { alloc::format!(" from {}/{}", IpFmt(r.src), r.src_mask.count_ones()) } else { String::new() };
            alloc::format!("route {}/{} via {}{}\n", IpFmt(r.net), r.mask.count_ones(), IpFmt(r.gw), from)
        })
        .collect()
}

/// The running configuration with counters (and a pending rollback).
pub fn show_text(sys: &mut dyn Sys) -> String {
    let Some(net) = sys.net() else { return String::new() };
    let mut out = String::new();
    for i in 0..net.nic_count() {
        let Some(n) = net.nic_info(i) else { continue };
        let addr = if n.ip == 0 { String::from("none") } else { alloc::format!("{}/{}", IpFmt(n.ip), n.mask.count_ones()) };
        out += &alloc::format!("{} mac {}  ip {}  gw {}  mtu {}\n", net.nic_name(i), MacFmt(n.mac), addr, IpFmt(n.gw), n.mtu);
        let extra = net.extra_addrs(i);
        if !extra.is_empty() {
            out += &alloc::format!("     extra ({}) {}\n", extra.len(), fmt_ip_list(&extra));
        }
        out += &alloc::format!("     rx {}  tx {}  rx_dropped {}  tx_dropped {}\n", n.rx, n.tx, n.rx_dropped, n.tx_dropped);
    }
    if let Some(a) = sys.admin() {
        out += &fmt_routes(&a.net_running().routes);
    }
    if let Some(s) = sys.admin().and_then(|a| a.net_pending()) {
        out += &alloc::format!("NOT CONFIRMED: the previous configuration comes back in {s} s (confirm or save to keep this)\n");
    }
    out
}

pub fn show(sys: &mut dyn Sys) {
    let t = show_text(sys);
    sys.print(&t);
}

fn find(conf: &[IfConf], name: &str) -> Result<usize, String> {
    conf.iter().position(|c| c.name() == name).ok_or_else(|| alloc::format!("no interface {name}\n"))
}

/// A leading interface name, or interface 0.
fn split<'a, 'b>(conf: &[IfConf], args: &'a [&'b str]) -> Result<(usize, &'a [&'b str]), String> {
    match args.first() {
        Some(a) if a.starts_with("nic") => Ok((find(conf, a)?, &args[1..])),
        _ => Ok((0, args)),
    }
}

/// `from a.b.c.d[/n]` of a route (nothing: from anywhere).
fn parse_from(args: &[&str]) -> Result<(u32, u32), String> {
    match args {
        [] => Ok((0, 0)),
        ["from", s] => {
            let (a, m) = if s.contains('/') { parse_cidr(s) } else { parse_ip(s).map(|a| (a, !0)) }.ok_or_else(|| String::from(USAGE))?;
            Ok((a & m, m))
        }
        _ => Err(String::from(USAGE)),
    }
}

/// Apply `ip` arguments to a configuration.
pub fn edit_ip(net: &mut NetConf, args: &[&str]) -> Result<(), String> {
    match args {
        ["route", "add", cidr, gw, from @ ..] => {
            let ((n, mask), gw) = parse_cidr(cidr).zip(parse_ip(gw)).ok_or_else(|| String::from(USAGE))?;
            let (src, src_mask) = parse_from(from)?;
            let net_ = n & mask;
            net.routes.retain(|r| (r.net, r.mask, r.src, r.src_mask) != (net_, mask, src, src_mask));
            net.routes.push(RouteConf { net: net_, mask, gw, src, src_mask });
            return Ok(());
        }
        ["route", "del", cidr, from @ ..] => {
            let (n, mask) = parse_cidr(cidr).ok_or_else(|| String::from(USAGE))?;
            let (src, src_mask) = parse_from(from)?;
            let before = net.routes.len();
            net.routes.retain(|r| (r.net, r.mask, r.src, r.src_mask) != (n & mask, mask, src, src_mask));
            if net.routes.len() == before {
                return Err(alloc::format!("no route {cidr}\n"));
            }
            return Ok(());
        }
        _ => {}
    }
    let conf = &mut net.ifs;
    match args {
        ["vlan", "add", parent, id] => {
            let p = find(conf, parent)?;
            if conf[p].vlan.is_some() {
                return Err(String::from("a VLAN goes on a NIC\n"));
            }
            let vid = id.parse::<u16>().ok().filter(|v| (1..=4094).contains(v)).ok_or_else(|| String::from("VLAN id must be 1..4094\n"))?;
            let c = IfConf { phys: conf[p].phys, vlan: Some(vid), mtu: 1500, ..IfConf::default() };
            if conf.iter().any(|x| x.name() == c.name()) {
                return Err(alloc::format!("{} exists\n", c.name()));
            }
            conf.push(c);
            return Ok(());
        }
        ["vlan", "del", name] => {
            let i = find(conf, name)?;
            if conf[i].vlan.is_none() {
                return Err(alloc::format!("{name} is not a VLAN\n"));
            }
            conf.remove(i);
            return Ok(());
        }
        _ => {}
    }
    let (i, rest) = split(conf, args)?;
    let c = &mut conf[i];
    match rest {
        ["none"] => (c.ip, c.mask, c.gw) = (0, 0, 0),
        [op @ ("add" | "del"), list] => {
            let l = parse_ip_list(list).ok_or_else(|| String::from(USAGE))?;
            c.extra.retain(|x| l.binary_search(x).is_err());
            if *op == "add" {
                c.extra.extend(l);
                c.extra.sort_unstable();
                c.extra.dedup();
            }
            if c.extra.len() > 4096 {
                return Err(String::from("at most 4096 extra addresses\n"));
            }
        }
        [cidr, gw @ ..] if gw.len() <= 1 => {
            let (ip, mask) = parse_cidr(cidr).ok_or_else(|| String::from(USAGE))?;
            let gw = match gw.first() {
                Some(g) => parse_ip(g).ok_or_else(|| String::from(USAGE))?,
                None => c.gw,
            };
            (c.ip, c.mask, c.gw) = (ip, mask, gw);
        }
        _ => return Err(String::from(USAGE)),
    }
    Ok(())
}

pub fn edit_mtu(net: &mut NetConf, args: &[&str]) -> Result<(), String> {
    let conf = &mut net.ifs[..];
    let (i, rest) = split(conf, args)?;
    match rest {
        [m] => {
            conf[i].mtu = m.parse::<u16>().ok().filter(|m| (576..=1500).contains(m)).ok_or_else(|| String::from("MTU must be 576..1500\n"))?;
            Ok(())
        }
        _ => Err(String::from(USAGE)),
    }
}

/// Lines only in `a` prefixed "- ", lines only in `b` prefixed "+ ".
fn diff(a: &str, b: &str) -> String {
    let (la, lb): (Vec<&str>, Vec<&str>) = (a.lines().collect(), b.lines().collect());
    let mut out = String::new();
    for l in &la {
        if !lb.contains(l) {
            out += &alloc::format!("- {l}\n");
        }
    }
    for l in &lb {
        if !la.contains(l) {
            out += &alloc::format!("+ {l}\n");
        }
    }
    if out.is_empty() {
        out += "(same as running)\n";
    }
    out
}

/// One network command (`words` include the command name): its output.
pub fn run(sys: &mut dyn Sys, words: &[&str]) -> Result<String, String> {
    let Some(admin) = sys.admin() else { return Err(String::from("not permitted\n")) };
    let running = admin.net_running();
    match words {
        ["ip"] | ["mtu"] => {}
        ["ip", args @ ..] | ["mtu", args @ ..] => {
            let mut c = running;
            if words[0] == "ip" { edit_ip(&mut c, args)? } else { edit_mtu(&mut c, args)? }
            admin.net_set_running(&c).map_err(|e| e + "\n")?;
        }
        ["cand"] => {
            let Some(c) = admin.net_candidate() else { return Ok(String::from("no candidate (cand ip ... starts one)\n")) };
            let state = if admin.net_applied() { "in effect (revert / discard / save)" } else { "not in effect" };
            return Ok(alloc::format!("candidate, {state}:\n{}changes against what runs:\n{}", fmt_conf(&c), diff(&fmt_conf(&running), &fmt_conf(&c))));
        }
        ["cand", cmd @ ("ip" | "mtu"), args @ ..] => {
            let mut c = admin.net_candidate().unwrap_or(running.clone());
            if *cmd == "ip" { edit_ip(&mut c, args)? } else { edit_mtu(&mut c, args)? }
            let d = diff(&fmt_conf(&running), &fmt_conf(&c));
            admin.net_set_candidate(Some(c));
            return Ok(alloc::format!("candidate changes (not in effect; apply to use them):\n{d}"));
        }
        ["stats"] => return Ok(admin.perf_report() + "\n"),
        ["stats", "reset"] => {
            admin.perf_reset();
            return Ok(String::from("peaks reset\n"));
        }
        ["discard"] => {
            let was = admin.net_applied();
            admin.net_discard();
            if !was {
                return Ok(String::from("candidate dropped\n"));
            }
        }
        ["revert"] => {
            if !admin.net_revert() {
                return Ok(String::from("nothing applied to revert\n"));
            }
        }
        ["apply", rest @ ..] if rest.len() <= 1 => {
            let seconds = match rest.first() {
                Some(m) => m.parse::<u32>().map_err(|_| String::from(USAGE))?,
                None => DEFAULT_APPLY_SECONDS,
            };
            admin.net_apply(seconds).map_err(|e| e + "\n")?;
        }
        ["confirm"] => {
            if !admin.net_confirm() {
                return Ok(String::from("nothing to confirm\n"));
            }
            return Ok(String::from("confirmed: no automatic revert (revert still works; save keeps it across reboots)\n"));
        }
        ["save"] => {
            return if admin.net_save() { Ok(String::from("saved: used from the next boot on\n")) } else { Err(String::from("save failed (no boot disk?)\n")) };
        }
        _ => return Err(String::from(USAGE)),
    }
    Ok(show_text(sys))
}

/// Tab completion for the console commands: candidates for the word after
/// `words` (`commands` for the first one).
pub fn complete(sys: &mut dyn Sys, words: &[&str], commands: &[&str]) -> Vec<String> {
    let own = |l: &[&str]| l.iter().map(|s| String::from(*s)).collect::<Vec<_>>();
    let nics = |sys: &mut dyn Sys, vlan: Option<bool>| -> Vec<String> {
        let Some(net) = sys.net() else { return Vec::new() };
        (0..net.nic_count()).map(|i| net.nic_name(i)).filter(|n| vlan.is_none_or(|v| n.contains('.') == v)).collect()
    };
    let w = match words {
        ["cand"] => return own(&["ip", "mtu"]),
        ["cand", rest @ ..] => rest,
        _ => words,
    };
    match w {
        [] => own(commands),
        ["ip"] => {
            let mut l = nics(sys, None);
            l.extend(own(&["add", "del", "none", "vlan", "route"]));
            l
        }
        ["ip", "vlan" | "route"] => own(&["add", "del"]),
        ["ip", "vlan", "add"] => nics(sys, Some(false)),
        ["ip", "vlan", "del"] => nics(sys, Some(true)),
        ["ip", n] if n.starts_with("nic") => own(&["add", "del", "none"]),
        ["mtu"] => nics(sys, None),
        ["mod"] => own(&["rm", "switch"]),
        ["mod", _] | ["cfg"] => sys.modules().into_iter().map(String::from).collect(),
        ["mod", "rm" | "switch", _] => own(&["native", "wasm"]),
        ["crash"] => own(&["clear"]),
        ["log"] => own(&["prev", "this"]),
        _ => Vec::new(),
    }
}

/// What `apply` would change, for asking first.
pub fn apply_preview(sys: &mut dyn Sys) -> Option<String> {
    let admin = sys.admin()?;
    let c = admin.net_candidate()?;
    Some(diff(&fmt_conf(&admin.net_running()), &fmt_conf(&c)))
}

/// Console form: print the result.
/// A question the console is waiting on (see `console_line`).
pub enum Ask {
    /// "apply these changes?": the apply line to run on yes
    Apply(String),
    /// "keep these changes?" after an apply (as iptables-apply asks); when
    /// it was last shown
    Keep(u64),
}

/// While "keep these changes?" waits: show it again every few seconds with
/// the time left (other output may have pushed it away), and say so when the
/// timer reverted. Call from the console module's poll.
pub fn console_tick(sys: &mut dyn Sys, ask: &mut Option<Ask>) {
    let Some(Ask::Keep(shown)) = ask else { return };
    let now = sys.now_ms();
    match sys.admin().and_then(|a| a.net_pending()) {
        None => {
            *ask = None;
            sys.print("\nno answer: the previous configuration is back (the candidate stays)\n");
            // the console's prompt follows
        }
        Some(left) if now >= *shown + 3000 => {
            *shown = now;
            sys.print(&alloc::format!("\nkeep these changes? [y/N] ({left} s left) "));
        }
        _ => {}
    }
}

/// Console handling of the network commands, with the two questions around
/// `apply`: before (showing the changes) and after (keep, or revert; no
/// answer reverts when the timer runs out). True if `line` was handled.
pub fn console_line(sys: &mut dyn Sys, ask: &mut Option<Ask>, line: &str) -> bool {
    let answer = match line.trim() {
        "y" | "yes" | "Y" => Some(true),
        "n" | "no" | "N" | "" => Some(false),
        _ => None,
    };
    match (ask.take(), answer) {
        (Some(Ask::Apply(l)), Some(true)) => {
            let words: Vec<&str> = l.split_ascii_whitespace().collect();
            let out = run(sys, &words).unwrap_or_else(|e| e);
            sys.print(&out);
            if let Some(secs) = sys.admin().and_then(|a| a.net_pending()) {
                sys.print(&alloc::format!("keep these changes? [y/N] (reverted by itself in {secs} s) "));
                *ask = Some(Ask::Keep(sys.now_ms()));
            }
            return true;
        }
        (Some(Ask::Apply(_)), Some(false)) => {
            sys.print("not applied (the candidate stays)\n");
            return true;
        }
        (Some(Ask::Keep(_)), Some(true)) => {
            let ok = sys.admin().is_some_and(|a| a.net_confirm());
            sys.print(if ok { "kept; revert still goes back to before the first apply, save ends the round and stores it\n" } else { "too late: it was reverted already\n" });
            return true;
        }
        (Some(Ask::Keep(_)), Some(false)) => {
            let ok = sys.admin().is_some_and(|a| a.net_revert());
            sys.print(if ok { "reverted (the candidate stays: apply again, discard or edit it)\n" } else { "nothing to revert\n" });
            return true;
        }
        _ => {} // no question pending, or another command: just run it
    }
    let words: Vec<&str> = line.split_ascii_whitespace().collect();
    match words.first() {
        Some(&"apply") if words.len() <= 2 => {
            match apply_preview(sys) {
                Some(d) => {
                    sys.print(&alloc::format!("{d}apply these changes? [y/N] "));
                    *ask = Some(Ask::Apply(String::from(line)));
                }
                None => sys.print("no candidate (cand ip ... starts one)\n"),
            }
            true
        }
        Some(&("ip" | "mtu" | "cand" | "discard" | "revert" | "save")) => {
            console(sys, &words);
            true
        }
        _ => false,
    }
}

pub fn console(sys: &mut dyn Sys, words: &[&str]) {
    let t = run(sys, words).unwrap_or_else(|e| e);
    sys.print(&t);
}

/// A configuration as the commands that make it (`ip ...`, `mtu ...`), for
/// export: `conf_from_commands` on them gives it back.
pub fn conf_commands(net: &NetConf) -> Vec<String> {
    let mut out = Vec::new();
    for c in &net.ifs {
        let name = c.name();
        if let Some(v) = c.vlan {
            out.push(alloc::format!("ip vlan add nic{} {}", c.phys, v));
        }
        if c.ip != 0 {
            let gw = if c.gw != 0 { alloc::format!(" {}", IpFmt(c.gw)) } else { String::new() };
            out.push(alloc::format!("ip {} {}/{}{}", name, IpFmt(c.ip), c.mask.count_ones(), gw));
        }
        if !c.extra.is_empty() {
            out.push(alloc::format!("ip {} add {}", name, fmt_ip_list(&c.extra)));
        }
        if c.mtu != 1500 && c.mtu != 0 {
            out.push(alloc::format!("mtu {} {}", name, c.mtu));
        }
    }
    for r in &net.routes {
        let from = if r.src_mask != 0 { alloc::format!(" from {}/{}", IpFmt(r.src), r.src_mask.count_ones()) } else { String::new() };
        out.push(alloc::format!("ip route add {}/{} {}{}", IpFmt(r.net), r.mask.count_ones(), IpFmt(r.gw), from));
    }
    out
}

/// The configuration `cmds` (as `conf_commands` writes them) make on the
/// NICs of `base`: its VLANs, addresses and routes are not kept.
pub fn conf_from_commands(base: &NetConf, cmds: &[&str]) -> Result<NetConf, String> {
    let mut net = NetConf {
        ifs: base.ifs.iter().filter(|c| c.vlan.is_none()).map(|c| IfConf { phys: c.phys, vlan: None, mtu: 1500, ..IfConf::default() }).collect(),
        routes: Vec::new(),
    };
    for line in cmds {
        let w: Vec<&str> = line.split_whitespace().collect();
        let r = match w.as_slice() {
            ["ip", rest @ ..] => edit_ip(&mut net, rest),
            ["mtu", rest @ ..] => edit_mtu(&mut net, rest),
            _ => Err(String::from("not a network command\n")),
        };
        r.map_err(|e| alloc::format!("{}: {}", line, e.trim_end()))?;
    }
    Ok(net)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commands_round_trip() {
        let base = NetConf { ifs: alloc::vec![IfConf { phys: 0, mtu: 1500, ..IfConf::default() }, IfConf { phys: 1, mtu: 1500, ..IfConf::default() }], routes: Vec::new() };
        let cmds = [
            "ip nic0 203.0.113.240/24 203.0.113.1",
            "ip vlan add nic1 109",
            "ip nic1.109 198.51.100.1/24 198.51.100.254",
            "ip nic1.109 add 198.51.100.2-198.51.100.9,198.51.100.20",
            "mtu nic1.109 1400",
            "ip route add 0.0.0.0/0 198.51.100.254 from 10.20.0.0/24",
        ];
        let net = conf_from_commands(&base, &cmds).unwrap();
        let again = conf_commands(&net);
        let back = conf_from_commands(&base, &again.iter().map(String::as_str).collect::<Vec<_>>()).unwrap();
        assert_eq!(net, back);
        assert!(again.iter().any(|l| l == "ip route add 0.0.0.0/0 198.51.100.254 from 10.20.0.0/24"), "{again:?}");
        assert!(conf_from_commands(&base, &["ip nic7 1.2.3.4/24"]).is_err());
    }
}
