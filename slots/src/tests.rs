use super::*;
use std::vec;

struct Mem {
    data: Vec<u8>,
}

impl BlockDevice for Mem {
    fn read(&mut self, lba: u64, buf: &mut [u8]) -> bool {
        let o = lba as usize * 512;
        buf.copy_from_slice(&self.data[o..o + buf.len()]);
        true
    }
    fn write(&mut self, lba: u64, buf: &[u8]) -> bool {
        let o = lba as usize * 512;
        if o + buf.len() > self.data.len() {
            return false;
        }
        self.data[o..o + buf.len()].copy_from_slice(buf);
        true
    }
    fn sectors(&self) -> u64 {
        (self.data.len() / 512) as u64
    }
}

const ENV: u64 = 10;
const A: u64 = 100;
const B: u64 = 200;
const SECS: u64 = 50;

fn env_text(d: &Mem) -> String {
    let e = &d.data[ENV as usize * 512..ENV as usize * 512 + 1024];
    String::from_utf8_lossy(e).trim_end_matches('#').to_string()
}

fn disk(boot_slot: &str) -> Mem {
    let mut d = Mem { data: vec![0; 300 * 512] };
    let mut env = format!("# GRUB Environment Block\nboot_slot={boot_slot}\n").into_bytes();
    env.resize(1024, b'#');
    d.write(ENV, &env);
    d.write(A, b"\x7fELF-a");
    d.write(B, b"\x7fELF-b");
    d
}

fn cmdline(slot: char, trial: bool) -> String {
    format!("ip=1.2.3.4/24 rustros.slot={slot} rustros.trial={} rustros.slots={A},{B},{SECS} rustros.env={ENV}", trial as u8)
}

#[test]
fn finds_the_boot_disk() {
    let other = Mem { data: vec![0; 300 * 512] };
    let (_, u) = Updater::new(&cmdline('a', false), &mut vec![other, disk("a")]).ok().unwrap();
    assert_eq!(u.slot, 'a');
    assert!(!u.trial);
    assert!(Updater::new(&cmdline('a', false), &mut vec![Mem { data: vec![0; 300 * 512] }]).is_err());
    assert!(Updater::new("ip=1.2.3.4", &mut vec![disk("a")]).is_err());
}

#[test]
fn update_writes_the_other_slot_and_arms_a_trial() {
    let (mut d, mut u) = Updater::new(&cmdline('a', false), &mut vec![disk("a")]).ok().unwrap();
    let image: Vec<u8> = (0..20_000u32).map(|i| (i * 7) as u8).collect();
    assert!(u.begin());
    for chunk in image.chunks(777) {
        assert!(u.write(&mut d, chunk));
    }
    assert!(u.commit(&mut d));
    let b = B as usize * 512;
    assert_eq!(&d.data[b..b + image.len()], &image[..]);
    assert!(d.data[A as usize * 512..].starts_with(b"\x7fELF-a"), "running slot untouched");
    let env = env_text(&d);
    assert!(env.contains("boot_slot=a\n") && env.contains("try_slot=b\n"), "{env}");
}

#[test]
fn image_larger_than_a_slot_is_refused() {
    let (mut d, mut u) = Updater::new(&cmdline('a', false), &mut vec![disk("a")]).ok().unwrap();
    assert!(u.begin());
    assert!(!u.write(&mut d, &vec![1u8; SECS as usize * 512 + 1]));
    assert!(!u.commit(&mut d));
    assert!(!env_text(&d).contains("try_slot"));
}

#[test]
fn trial_boot_must_confirm_before_updating() {
    // GRUB booted slot b once (it cleared try_slot already)
    let (mut d, mut u) = Updater::new(&cmdline('b', true), &mut vec![disk("a")]).ok().unwrap();
    assert!(u.trial);
    assert!(!u.begin(), "no update while the rollback copy is still needed");
    assert!(u.confirm(&mut d));
    assert!(!u.trial);
    assert!(env_text(&d).contains("boot_slot=b\n"));
    assert!(u.begin());
}

#[test]
fn variables_survive_slot_changes() {
    let (mut d, mut u) = Updater::new(&cmdline('a', false), &mut vec![disk("a")]).ok().unwrap();
    assert!(u.set_vars(&mut d, &[("net_ip", "10.0.0.2/24"), ("net_gw", "10.0.0.1")]));
    assert!(!u.set_vars(&mut d, &[("x", "two\nlines")]));
    assert!(u.begin());
    assert!(u.write(&mut d, b"\x7fELF new kernel"));
    assert!(u.commit(&mut d));
    let env = env_text(&d);
    assert!(env.contains("net_ip=10.0.0.2/24\n") && env.contains("net_gw=10.0.0.1\n") && env.contains("try_slot=b\n"), "{env}");
    // what the next boot sees
    let (mut d, mut u) = Updater::new(&cmdline('b', true), &mut vec![d]).ok().unwrap();
    assert_eq!(u.get("net_ip"), Some("10.0.0.2/24"));
    assert!(u.set_vars(&mut d, &[("net_gw", "")]));
    assert_eq!(u.get("net_gw"), None);
    assert!(!env_text(&d).contains("net_gw"));
}
