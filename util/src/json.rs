//! A little JSON: parsing into a tree (numbers kept as their text, so
//! 64-bit ids stay exact) and quoting strings for writing it.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;


#[derive(Debug, Clone, PartialEq)]
pub enum Json {
    Str(String),
    Num(String),
    Bool(bool),
    Null,
    Arr(Vec<Json>),
    Obj(Vec<(String, Json)>),
}

impl Json {
    pub fn parse(text: &[u8]) -> Option<Json> {
        let mut p = 0;
        let v = value(text, &mut p)?;
        Some(v)
    }

    pub fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Obj(m) => m.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    pub fn at(&self, i: usize) -> Option<&Json> {
        match self {
            Json::Arr(a) => a.get(i),
            _ => None,
        }
    }

    pub fn path(&self, keys: &[&str]) -> Option<&Json> {
        keys.iter().try_fold(self, |v, k| v.get(k))
    }

    pub fn str(&self) -> Option<&str> {
        match self {
            Json::Str(s) => Some(s),
            _ => None,
        }
    }

    /// For showing: a string as it is, anything else in its JSON form.
    pub fn text(&self) -> String {
        match self {
            Json::Str(s) => s.clone(),
            Json::Num(n) => n.clone(),
            Json::Bool(b) => format!("{b}"),
            Json::Null => String::from("null"),
            _ => String::from("..."),
        }
    }
}

fn ws(t: &[u8], p: &mut usize) {
    while t.get(*p).is_some_and(|c| c.is_ascii_whitespace()) {
        *p += 1;
    }
}

fn value(t: &[u8], p: &mut usize) -> Option<Json> {
    ws(t, p);
    match *t.get(*p)? {
        b'{' => {
            *p += 1;
            let mut m = Vec::new();
            loop {
                ws(t, p);
                match *t.get(*p)? {
                    b'}' => {
                        *p += 1;
                        return Some(Json::Obj(m));
                    }
                    b',' => *p += 1,
                    _ => {
                        let Json::Str(k) = value(t, p)? else { return None };
                        ws(t, p);
                        if *t.get(*p)? != b':' {
                            return None;
                        }
                        *p += 1;
                        m.push((k, value(t, p)?));
                    }
                }
            }
        }
        b'[' => {
            *p += 1;
            let mut a = Vec::new();
            loop {
                ws(t, p);
                match *t.get(*p)? {
                    b']' => {
                        *p += 1;
                        return Some(Json::Arr(a));
                    }
                    b',' => *p += 1,
                    _ => a.push(value(t, p)?),
                }
            }
        }
        b'"' => {
            *p += 1;
            let mut s = Vec::new();
            loop {
                let c = *t.get(*p)?;
                *p += 1;
                match c {
                    b'"' => return Some(Json::Str(String::from_utf8_lossy(&s).into_owned())),
                    b'\\' => {
                        let e = *t.get(*p)?;
                        *p += 1;
                        match e {
                            b'n' => s.push(b'\n'),
                            b't' => s.push(b'\t'),
                            b'r' => s.push(b'\r'),
                            b'b' | b'f' => {}
                            b'u' => {
                                let h = core::str::from_utf8(t.get(*p..*p + 4)?).ok()?;
                                *p += 4;
                                let c = char::from_u32(u32::from_str_radix(h, 16).ok()?).unwrap_or('?');
                                s.extend_from_slice(c.encode_utf8(&mut [0; 4]).as_bytes());
                            }
                            e => s.push(e),
                        }
                    }
                    c => s.push(c),
                }
            }
        }
        b't' if t[*p..].starts_with(b"true") => {
            *p += 4;
            Some(Json::Bool(true))
        }
        b'f' if t[*p..].starts_with(b"false") => {
            *p += 5;
            Some(Json::Bool(false))
        }
        b'n' if t[*p..].starts_with(b"null") => {
            *p += 4;
            Some(Json::Null)
        }
        _ => {
            let start = *p;
            while t.get(*p).is_some_and(|c| matches!(c, b'-' | b'+' | b'.' | b'e' | b'E' | b'0'..=b'9')) {
                *p += 1;
            }
            (*p > start).then(|| Json::Num(String::from_utf8_lossy(&t[start..*p]).into_owned()))
        }
    }
}


impl Json {
    /// An integer number (exactly, from its text).
    pub fn u64(&self) -> Option<u64> {
        match self {
            Json::Num(n) => n.parse().ok(),
            _ => None,
        }
    }

    pub fn i64(&self) -> Option<i64> {
        match self {
            Json::Num(n) => n.parse().ok(),
            _ => None,
        }
    }

    pub fn bool(&self) -> Option<bool> {
        match self {
            Json::Bool(b) => Some(*b),
            _ => None,
        }
    }
}

/// `s` as a JSON string, quoted.
pub fn quote(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 2);
    o.push('"');
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            '\r' => o.push_str("\\r"),
            '\t' => o.push_str("\\t"),
            c if (c as u32) < 0x20 => o.push_str(&format!("\\u{:04x}", c as u32)),
            c => o.push(c),
        }
    }
    o.push('"');
    o
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_and_quote() {
        let j = Json::parse(br#"{"id":1792202040988708463,"a":[1,{"b":"x\"y"}],"ok":true,"n":null}"#).unwrap();
        assert_eq!(j.get("id").and_then(Json::u64), Some(1792202040988708463));
        assert_eq!(j.get("a").and_then(|a| a.at(1)).and_then(|o| o.get("b")).and_then(Json::str), Some("x\"y"));
        assert_eq!(j.get("ok").and_then(Json::bool), Some(true));
        assert_eq!(quote("a\"b\\c\n\u{1}"), r#""a\"b\\c\n\u0001""#);
        let back = Json::parse(quote("tab\there").as_bytes()).unwrap();
        assert_eq!(back.str(), Some("tab\there"));
    }
}
