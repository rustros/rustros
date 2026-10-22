//! PEM as people paste it into one-line settings.

use alloc::format;
use alloc::string::String;

/// A PEM value as typed on one line (newlines as spaces or `\n`), made
/// PEM again: each BEGIN … END block with its base64 rewrapped.
pub fn normalize(v: &str) -> String {
    let v = v.replace("\\n", "\n");
    let mut out = String::new();
    let mut rest = v.as_str();
    while let Some(b) = rest.find("-----BEGIN ") {
        let after = &rest[b + 11..];
        let Some(e) = after.find("-----") else { break };
        let label = &after[..e];
        let body_start = b + 11 + e + 5;
        let end_mark = format!("-----END {label}-----");
        let Some(end) = rest[body_start..].find(&end_mark) else { break };
        let body: String = rest[body_start..body_start + end].chars().filter(|c| !c.is_whitespace()).collect();
        out += &format!("-----BEGIN {label}-----\n");
        for line in body.as_bytes().chunks(64) {
            out += core::str::from_utf8(line).unwrap_or("");
            out.push('\n');
        }
        out += &format!("{end_mark}\n");
        rest = &rest[body_start + end + end_mark.len()..];
    }
    out
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pem_from_one_line() {
        let one = "-----BEGIN PRIVATE KEY----- MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg -----END PRIVATE KEY-----";
        assert_eq!(normalize(one), "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg\n-----END PRIVATE KEY-----\n");
        let esc = "-----BEGIN CERTIFICATE-----\\nAAAA\\nBBBB\\n-----END CERTIFICATE-----\\n-----BEGIN CERTIFICATE-----\\nCCCC\\n-----END CERTIFICATE-----";
        assert_eq!(normalize(esc), "-----BEGIN CERTIFICATE-----\nAAAABBBB\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nCCCC\n-----END CERTIFICATE-----\n");
    }

}
