//! Error types: unified conversion into [`lattice_core::LatticeError`] (⑤ §0.5/§0.6), plus HTTP response wrappers.

pub use lattice_core::LatticeError;
pub type Result<T> = std::result::Result<T, LatticeError>;

pub use lattice_core::protocol::ErrorCode;

use axum::http::{HeaderName, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;

/// `ApiErr`: converts [`LatticeError`] into an HTTP response conforming to ⑤ §0.5 (includes `trace_id`, `Retry-After`).
pub struct ApiErr(pub LatticeError);

impl From<LatticeError> for ApiErr {
    fn from(e: LatticeError) -> Self {
        ApiErr(e)
    }
}

impl std::fmt::Debug for ApiErr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl IntoResponse for ApiErr {
    fn into_response(self) -> Response {
        let e = self.0;
        let status = StatusCode::from_u16(e.http_status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        let trace = lattice_core::ids::new_id();
        let mut resp = (status, Json(e.body(&trace))).into_response();
        if status == StatusCode::TOO_MANY_REQUESTS {
            resp.headers_mut()
                .insert(HeaderName::from_static("retry-after"), HeaderValue::from_static("1"));
        }
        resp.headers_mut().insert(
            HeaderName::from_static("x-trace-id"),
            HeaderValue::from_str(&trace).unwrap_or(HeaderValue::from_static("")),
        );
        resp
    }
}

pub type ApiResult<T> = std::result::Result<T, ApiErr>;

pub fn internal(msg: impl Into<String>) -> LatticeError {
    LatticeError::internal(msg)
}

pub fn protocol(msg: impl Into<String>) -> LatticeError {
    LatticeError::protocol(msg)
}

pub fn format(msg: impl Into<String>) -> LatticeError {
    LatticeError::format(msg)
}

pub fn not_found(msg: impl Into<String>) -> LatticeError {
    LatticeError::not_found(msg)
}

pub fn bad_request(msg: impl Into<String>) -> LatticeError {
    LatticeError::protocol(msg)
}

pub fn forbidden(msg: impl Into<String>) -> LatticeError {
    LatticeError::forbidden(msg)
}

pub fn unauthorized(msg: impl Into<String>) -> LatticeError {
    LatticeError::auth_fail(msg)
}

/// SQLx error → INTERNAL; never leak SQL details to clients.
pub fn db(e: sqlx::Error) -> LatticeError {
    tracing::error!(error = %e, "database error");
    LatticeError::internal("storage unavailable").with_detail("dep", serde_json::json!("pg"))
}

/// Redis error → INTERNAL, tagged with the dependency name for `/v1/ready` and alerting (⑤ §0.6 `details.dep`).
pub fn redis(e: redis::RedisError) -> LatticeError {
    tracing::error!(error = %e, "redis error");
    LatticeError::internal("cache unavailable").with_detail("dep", serde_json::json!("redis"))
}
