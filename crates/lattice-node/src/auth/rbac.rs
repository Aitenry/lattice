//! RBAC and request context (⑤ §0.2 "role source").
//!
//! The **authoritative value of the role is `users.role`** (⑥ §2.3 / design §17.11): on login and refresh,
//! `transport::http::auth` reads that column and signs it into the access JWT; the `role` inside the token is only
//! **a snapshot for the token lifetime** (TTL 900s). Server-side authorization trusts the snapshot and does not query PG per request
//! (so the admin plane does not make PG a hotspot). When "immediate effect" is needed, an administrator revokes the user's devices to force re-login
//! (⑤ §8.2 `DELETE /v1/admin/devices/{id}`).
//!
//! Before v0.6 roles had nowhere to live, so `dynamic_config['rbac.roles']` held `{user_id: role}`
//! with a `[admin] bootstrap_username` fallback — a second source for the same fact
//! (design §17.14-6); that was removed after the ⑥ §9.1 D14 backfill.

use std::collections::HashMap;

use std::sync::Arc;

use axum::extract::FromRequestParts;
use axum::http::request::Parts;

use crate::auth::jwt::{Claims, Role};
use crate::error::{self, Result};
use crate::state::AppState;

/// Authenticated principal.
#[derive(Debug, Clone)]
pub struct AuthUser {
    pub user_id: String,
    pub device_id: String,
    pub role: Role,
}

impl AuthUser {
    pub fn require_read(&self) -> Result<()> {
        if self.role.can_read() {
            Ok(())
        } else {
            Err(error::forbidden("insufficient role"))
        }
    }

    pub fn require_act(&self) -> Result<()> {
        if self.role.can_act() {
            Ok(())
        } else {
            Err(error::forbidden("insufficient role").with_reason("rbac"))
        }
    }

    pub fn require_change(&self) -> Result<()> {
        if self.role.can_change() {
            Ok(())
        } else {
            Err(error::forbidden("insufficient role").with_reason("rbac"))
        }
    }

    pub fn is_admin(&self) -> bool {
        self.role == Role::Admin
    }
}

/// Extract the principal from `Authorization: Bearer` (shared by the message plane and parts of the admin plane).
pub fn authenticate(state: &AppState, headers: &axum::http::HeaderMap) -> Result<AuthUser> {
    let raw = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| error::unauthorized("missing bearer token"))?;
    let token = raw
        .strip_prefix("Bearer ")
        .or_else(|| raw.strip_prefix("bearer "))
        .ok_or_else(|| error::unauthorized("malformed authorization header"))?;
    // Key hot rotation: AppState::verify_jwt takes a snapshot internally (current+previous dual-key window);
    // failures are counted by reason in lattice_key_verification_failures_total.
    let claims: Claims = state.verify_jwt(token)?;
    let role = resolve_role(state, &claims.sub, &claims.role);
    Ok(AuthUser { user_id: claims.sub, device_id: claims.dev, role })
}

/// Resolve the role from the token snapshot (`claims.role` is signed from `users.role`).
///
/// Kept instead of calling `Role::parse` directly: unknown values degrade to `user` (least privilege),
/// and it leaves room to layer "temporary downgrade" (e.g. risk-control freeze) over the snapshot without touching call sites.
///
/// Migration compatibility is also centralized in [`Role::parse`]: the old claim `role=viewer` parses as `User`
/// (read-only unchanged), so the rename needs no forced invalidation of in-flight tokens.
pub fn resolve_role(_state: &AppState, _user_id: &str, claim_role: &str) -> Role {
    Role::parse(claim_role)
}

/// Axum extractor: parse `AuthUser` straight from request headers (on rejection emit the ⑤ §0.5 error body).
#[axum::async_trait]
impl FromRequestParts<Arc<AppState>> for AuthUser {
    type Rejection = crate::error::ApiErr;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> std::result::Result<Self, Self::Rejection> {
        Ok(authenticate(state, &parts.headers)?)
    }
}

/// Parse the `{user_id: role}` map. **Migration only**: one-shot import of the old
/// `dynamic_config['rbac.roles']` into `users.role` (⑥ §9.1 D14).
/// Not read at runtime anymore — otherwise "one fact, two sources" comes back.
pub fn role_map_from(value: &serde_json::Value) -> HashMap<String, String> {
    match value {
        serde_json::Value::Object(m) => m
            .iter()
            .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
            .collect(),
        _ => HashMap::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn role_gates() {
        let user = AuthUser { user_id: "u".into(), device_id: "d".into(), role: Role::User };
        assert!(user.require_read().is_ok());
        assert!(user.require_act().is_err());
        assert_eq!(user.require_change().unwrap_err().code, lattice_core::ErrorCode::Forbidden);

        let ops = AuthUser { role: Role::Ops, ..user.clone() };
        assert!(ops.require_act().is_ok());
        assert!(ops.require_change().is_err());

        let admin = AuthUser { role: Role::Admin, ..user };
        assert!(admin.require_change().is_ok());
    }

    #[test]
    fn role_map_parsing() {
        let v = serde_json::json!({"u1":"admin","u2":"ops","bad":1});
        let m = role_map_from(&v);
        assert_eq!(m.get("u1").map(String::as_str), Some("admin"));
        assert!(m.get("bad").is_none());
    }
}
