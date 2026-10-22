//! Secret settings (passwords): which keys hold one, and keeping their
//! values off the screen and out of the console log.

/// A module setting whose value is a secret: never shown or logged.
pub fn is_secret(key: &str) -> bool {
    key == "password" || key == "pwhash" || key.ends_with(".password") || key.starts_with("user.")
}

/// In a console line, where the secret value starts: after
/// `cfg <module> <secret key> ` (None if the line sets no secret).
pub fn value_start(line: &str) -> Option<usize> {
    let mut words = 0;
    let mut in_word = false;
    let mut key_start = 0;
    for (i, c) in line.char_indices() {
        if c == ' ' {
            if in_word {
                words += 1;
                in_word = false;
                if words == 3 {
                    let w: alloc::vec::Vec<&str> = line[..i].split_ascii_whitespace().collect();
                    return (w[0] == "cfg" && is_secret(&line[key_start..i])).then_some(i + 1);
                }
            }
        } else if !in_word {
            in_word = true;
            key_start = i;
        }
    }
    None
}

/// The line as it may be shown: a secret value as `*`s.
pub fn masked(line: &str) -> alloc::string::String {
    match value_start(line) {
        Some(v) => alloc::format!("{}{}", &line[..v], "*".repeat(line[v..].chars().count())),
        None => alloc::string::String::from(line),
    }
}

/// Mask secret values in console log text, in place: the rest of a line
/// after `cfg <module> <secret key> `, or after `<secret key> = ` (a
/// listing). True if anything changed.
pub fn redact(text: &mut [u8]) -> bool {
    let mut changed = false;
    let mut start = 0;
    while start < text.len() {
        let end = text[start..].iter().position(|&b| b == b'\n' || b == b'\r').map_or(text.len(), |p| start + p);
        let line = &text[start..end];
        let mut from = None;
        // the command may follow a prompt: look for "cfg " anywhere
        if let Some(p) = line.windows(4).position(|w| w == b"cfg ") {
            if let Ok(s) = core::str::from_utf8(&line[p..]) {
                from = value_start(s).map(|v| p + v);
            }
        }
        if from.is_none() {
            if let Some(p) = line.windows(3).position(|w| w == b" = ") {
                let key = core::str::from_utf8(&line[..p]).unwrap_or("").rsplit(' ').next().unwrap_or("");
                if is_secret(key) && &line[p + 3..] != b"***" && &line[p + 3..] != b"(set)" {
                    from = Some(p + 3);
                }
            }
        }
        if let Some(f) = from {
            for b in &mut text[start + f..end] {
                if *b != b'*' {
                    *b = b'*';
                    changed = true;
                }
            }
        }
        start = end + 1;
    }
    changed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys() {
        assert!(is_secret("password") && is_secret("user.alice") && is_secret("pwhash") && is_secret("api.password"));
        assert!(!is_secret("allow") && !is_secret("port") && !is_secret("srcnat.10.0.0.1"));
    }

    #[test]
    fn typing() {
        assert_eq!(value_start("cfg webadmin password "), Some(22));
        assert_eq!(value_start("cfg webadmin password"), None, "still typing the key");
        assert_eq!(value_start("cfg webadmin port "), None);
        assert_eq!(value_start("ip nic0 password "), None);
        assert_eq!(masked("cfg  l2tp user.bob s3cr et"), "cfg  l2tp user.bob *******");
        assert_eq!(masked("cfg nat srcnat.1.2.3.4 5.6.7.8"), "cfg nat srcnat.1.2.3.4 5.6.7.8");
    }

    #[test]
    fn log() {
        let mut t = b"rustros> cfg webadmin password hunter2\nok\npwhash = 0123abcd\nport = 8080\nuser.test = ***\nnat: srcnat 1 -> 2\n".to_vec();
        assert!(redact(&mut t));
        assert_eq!(
            core::str::from_utf8(&t).unwrap(),
            "rustros> cfg webadmin password *******\nok\npwhash = ********\nport = 8080\nuser.test = ***\nnat: srcnat 1 -> 2\n"
        );
        assert!(!redact(&mut t), "nothing left");
    }
}
