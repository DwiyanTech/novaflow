//! Request normalization pipeline.
//!
//! The single biggest weakness of regex-on-raw-input WAFs is encoding
//! evasion (`%27OR%271%3D1`, double encoding, HTML entities, null bytes,
//! SQL comments). Every serious engine (ModSecurity transformations,
//! libinjection, SafeLine's decoder) normalizes BEFORE matching.
//!
//! The normalized string is ONLY used for inspection — the original
//! request is forwarded upstream untouched.

/// Full inspection pipeline: repeated percent-decode, HTML entity decode,
/// control-character cleanup. Case folding is done separately so callers
/// can choose.
pub fn normalize(raw: &str) -> String {
    let mut s = raw.to_string();
    // Attackers double- and triple-encode; decode until stable (max 4).
    for _ in 0..4 {
        let decoded = percent_decode(&s);
        if decoded == s {
            break;
        }
        s = decoded;
    }
    let s = html_entity_decode(&s);
    cleanup_controls(&s)
}

/// Lowercased copy for case-insensitive semantic analysis.
pub fn fold(s: &str) -> String {
    s.to_lowercase()
}

/// Replace SQL comments with spaces: `/* ... */`, `-- ...` (to EOL) and
/// `# ...` (to EOL). Comment stuffing is the classic keyword-splitting
/// evasion: `UN/**/ION SEL/**/ECT`.
pub fn strip_sql_comments(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < bytes.len() {
        if i + 1 < bytes.len() && bytes[i] == b'/' && bytes[i + 1] == b'*' {
            // skip to closing */
            let mut j = i + 2;
            while j + 1 < bytes.len() && !(bytes[j] == b'*' && bytes[j + 1] == b'/') {
                j += 1;
            }
            i = if j + 1 < bytes.len() {
                j + 2
            } else {
                bytes.len()
            };
            out.push(' ');
        } else if i + 1 < bytes.len() && bytes[i] == b'-' && bytes[i + 1] == b'-' {
            // -- to end of line
            let mut j = i + 2;
            while j < bytes.len() && bytes[j] != b'\n' {
                j += 1;
            }
            i = j;
            out.push(' ');
        } else if bytes[i] == b'#' {
            let mut j = i + 1;
            while j < bytes.len() && bytes[j] != b'\n' {
                j += 1;
            }
            i = j;
            out.push(' ');
        } else {
            out.push(bytes[i] as char);
            i += 1;
        }
    }
    out
}

/// `%XX` percent decoding (invalid sequences pass through unchanged).
/// `+` becomes a space — this string is only inspected, never forwarded.
fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                out.push((h << 4) | l);
                i += 3;
                continue;
            }
        }
        if bytes[i] == b'+' {
            out.push(b' ');
        } else {
            out.push(bytes[i]);
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Decode `&#x41;`, `&#65;` and the common named entities used in XSS.
fn html_entity_decode(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'&' {
            if let Some((decoded, consumed)) = try_entity(&input[i..]) {
                out.push(decoded);
                i += consumed;
                continue;
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

fn try_entity(s: &str) -> Option<(char, usize)> {
    let end = s.find(';')?;
    if !(2..=10).contains(&end) {
        return None;
    }
    let body = &s[1..end];
    if let Some(hex) = body.strip_prefix("#x").or_else(|| body.strip_prefix("#X")) {
        let v = u32::from_str_radix(hex, 16).ok()?;
        return char::from_u32(v).map(|c| (c, end + 1));
    }
    if let Some(dec) = body.strip_prefix('#') {
        let v: u32 = dec.parse().ok()?;
        return char::from_u32(v).map(|c| (c, end + 1));
    }
    let c = match body {
        "lt" => '<',
        "gt" => '>',
        "amp" => '&',
        "quot" => '"',
        "apos" => '\'',
        "sol" => '/',
        "bsol" => '\\',
        _ => return None,
    };
    Some((c, end + 1))
}

/// Null bytes and control chars → space (they split tokens to fool
/// naive matchers: `<scr\0ipt>`, `SE\0LECT`).
fn cleanup_controls(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_control() && c != '\n' && c != '\t' {
                ' '
            } else {
                c
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_percent_encoding() {
        assert_eq!(normalize("%27%20OR%201%3D1"), "' OR 1=1");
    }

    #[test]
    fn decodes_double_encoding() {
        assert_eq!(normalize("%2527%2520OR"), "' OR");
    }

    #[test]
    fn decodes_entities() {
        assert_eq!(normalize("&lt;script&gt;"), "<script>");
        assert_eq!(normalize("&#x3c;script&#x3e;"), "<script>");
    }

    #[test]
    fn strips_sql_comments() {
        assert_eq!(
            fold(&strip_sql_comments("UN/**/ION SEL/**/ECT")),
            "un ion sel ect"
        );
        assert_eq!(strip_sql_comments("1' OR 1=1-- "), "1' OR 1=1 ");
    }

    #[test]
    fn removes_null_bytes() {
        assert_eq!(normalize("<scr\0ipt>"), "<scr ipt>");
    }

    #[test]
    fn plus_becomes_space() {
        assert_eq!(normalize("a+b"), "a b");
    }
}
