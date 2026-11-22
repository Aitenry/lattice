//! Unified error (response body shape from ⑤ §0.5 + status code mapping from ⑤ §0.6).

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::protocol::ErrorCode;

/// End-to-end error: REST response bodies, WS `error` frames, and internal stage errors share one representation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LatticeError {
    pub code: ErrorCode,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub envelope_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<Value>,
}

impl std::fmt::Display for LatticeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code.as_str(), self.message)
    }
}

impl std::error::Error for LatticeError {}

impl LatticeError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        LatticeError { code, message: message.into(), envelope_id: None, details: None }
    }

    pub fn protocol(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::Protocol, message)
    }
    pub fn auth_fail(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::AuthFail, message)
    }
    pub fn forbidden(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::Forbidden, message)
    }
    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::NotFound, message)
    }
    pub fn conflict(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::Conflict, message)
    }
    pub fn format(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::Format, message)
    }
    pub fn rate(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::Rate, message)
    }
    pub fn quota(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::Quota, message)
    }
    pub fn plugin(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::Plugin, message)
    }
    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::Internal, message)
    }
    pub fn too_large(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::TooLarge, message)
    }

    pub fn with_reason(mut self, reason: &str) -> Self {
        let d = self.details.get_or_insert_with(|| json!({}));
        if let Value::Object(map) = d {
            map.insert("reason".into(), Value::String(reason.into()));
        }
        self
    }

    pub fn with_detail(mut self, key: &str, value: Value) -> Self {
        let d = self.details.get_or_insert_with(|| json!({}));
        if let Value::Object(map) = d {
            map.insert(key.into(), value);
        }
        self
    }

    pub fn with_envelope(mut self, envelope_id: impl Into<String>) -> Self {
        self.envelope_id = Some(envelope_id.into());
        self
    }

    /// Error response body from ⑤ §0.5 (`trace_id` is injected by the HTTP layer).
    pub fn body(&self, trace_id: &str) -> Value {
        json!({
            "code": self.code.as_str(),
            "message": self.message,
            "envelope_id": self.envelope_id,
            "details": self.details,
            "trace_id": trace_id,
        })
    }

    pub fn http_status(&self) -> u16 {
        self.code.http_status()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn details_and_status() {
        let e = LatticeError::forbidden("not a member").with_reason("not_member");
        assert_eq!(e.http_status(), 403);
        let body = e.body("trace-1");
        assert_eq!(body["code"], "FORBIDDEN");
        assert_eq!(body["details"]["reason"], "not_member");
        assert_eq!(body["trace_id"], "trace-1");
    }

    #[test]
    fn too_large_hint() {
        let e = LatticeError::too_large("body too large")
            .with_detail("hint", serde_json::json!("use_ws_or_chunk"));
        assert_eq!(e.http_status(), 413);
    }
}
