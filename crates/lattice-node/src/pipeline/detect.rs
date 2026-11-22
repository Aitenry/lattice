//! Format detection (② §4.5 `detect`): `Content-Type` first; when missing or untrusted, fall back to magic bytes.
//!
//! In zero-knowledge mode (default) the server **does not unpack**; it only runs heuristics when header fields are untrusted (without parsing payload content).

/// Detection result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Detected {
    pub r#type: String,
    pub mime: String,
    /// Evidence: `declared` (trust header field) | `magic` (magic-byte heuristic) | `fallback`
    pub evidence: &'static str,
}

/// Common magic-number table (per the §6.1 examples: zip/png/mp4/protobuf heuristics).
const MAGICS: [(&[u8], &str, &str); 6] = [
    (&[0x50, 0x4b, 0x03, 0x04], "file", "application/zip"),
    (&[0x89, 0x50, 0x4e, 0x47], "image", "image/png"),
    (&[0xff, 0xd8, 0xff], "image", "image/jpeg"),
    (&[0x00, 0x00, 0x00, 0x18], "media", "video/mp4"),
    (&[0x1f, 0x8b], "file", "application/gzip"),
    (&[0x7b], "json", "application/json"),
];

pub fn detect(declared_content_type: &str, isinstance_trusted: bool, payload: &[u8]) -> Detected {
    if isinstance_trusted && !declared_content_type.is_empty() {
        let ty = type_from_mime(declared_content_type);
        return Detected {
            r#type: ty.to_string(),
            mime: declared_content_type.to_string(),
            evidence: "declared",
        };
    }

    for (magic, ty, mime) in MAGICS {
        if payload.len() >= magic.len() && &payload[..magic.len()] == magic {
            return Detected { r#type: ty.to_string(), mime: mime.to_string(), evidence: "magic" };
        }
    }

    Detected {
        r#type: "binary".to_string(),
        mime: if declared_content_type.is_empty() {
            "application/octet-stream".to_string()
        } else {
            declared_content_type.to_string()
        },
        evidence: "fallback",
    }
}

/// MIME → `type` namespace (§5).
pub fn type_from_mime(mime: &str) -> &'static str {
    let base = mime.split(';').next().unwrap_or(mime).trim();
    match base {
        "text/plain" => "text",
        "application/json" => "json",
        "application/xml" | "text/xml" => "xml",
        "application/protobuf" => "proto",
        "application/msgpack" => "msgpack",
        m if m.starts_with("image/") => "image",
        m if m.starts_with("video/") || m.starts_with("audio/") => "media",
        "application/vnd.lattice.stream" => "stream",
        _ => "binary",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn declared_wins_when_trusted() {
        let d = detect("image/png", true, b"not really a png");
        assert_eq!(d.r#type, "image");
        assert_eq!(d.evidence, "declared");
    }

    #[test]
    fn magic_used_when_untrusted() {
        let d = detect("", false, &[0x89, 0x50, 0x4e, 0x47, 0x00]);
        assert_eq!(d.r#type, "image");
        assert_eq!(d.evidence, "magic");
    }

    #[test]
    fn fallback_is_binary() {
        let d = detect("", false, &[0x01, 0x02, 0x03]);
        assert_eq!(d.r#type, "binary");
        assert_eq!(d.evidence, "fallback");
        assert_eq!(d.mime, "application/octet-stream");
    }

    #[test]
    fn mime_mapping() {
        assert_eq!(type_from_mime("application/json; charset=utf-8"), "json");
        assert_eq!(type_from_mime("video/mp4"), "media");
        assert_eq!(type_from_mime("application/octet-stream"), "binary");
    }
}
