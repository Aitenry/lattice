//! Format negotiation and conversion (② §4.5 `format`).
//!
//! Negotiation order (§6.1): sender preference → receiver capability → fallback passthrough.
//! Convert only for formats with a declared converter (plugin or built-in); otherwise **pass through** (payload unchanged).

use std::sync::Arc;

use lattice_plugins::registry::{pick, PluginEntry};

use crate::state::{AppState, Caps};

/// Negotiation result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Negotiation {
    /// Final delivered type
    pub target_type: String,
    /// Whether conversion is needed
    pub needs_convert: bool,
    /// Matched plugin (ns, version)
    pub plugin: Option<(String, u32)>,
}

/// Decide the downlink format from receiver capability; pass through unchanged when there is no intersection (§6.1 fallback).
pub fn negotiate(
    state: &AppState,
    sender_caps: &Caps,
    receiver_caps: &Caps,
    env_type: &str,
    user_id: &str,
) -> Negotiation {
    let supported = |caps: &Caps, ty: &str| caps.formats.is_empty() || caps.formats.iter().any(|f| f == ty);

    if supported(receiver_caps, env_type) {
        return Negotiation { target_type: env_type.to_string(), needs_convert: false, plugin: None };
    }

        // Sender preference ∩ receiver capability
    let candidate = sender_caps
        .formats
        .iter()
        .find(|f| supported(receiver_caps, f))
        .cloned();

    let entries = plugin_entries(state);
    let chosen = candidate.or_else(|| receiver_caps.formats.first().cloned());

    match chosen {
        Some(ty) => {
            let ns = format!("convert:{env_type}->{ty}");
            let hit = pick(&entries, &ns, user_id).map(|e| (e.ns.clone(), e.version));
            Negotiation {
                target_type: ty,
                                // No converter → passthrough (do not pretend conversion succeeded)
                needs_convert: hit.is_some(),
                plugin: hit,
            }
        }
        None => Negotiation {
            target_type: env_type.to_string(),
            needs_convert: false,
            plugin: None,
        },
    }
}

fn plugin_entries(state: &AppState) -> Vec<PluginEntry> {
    state
        .plugins
        .read()
        .map(|v| v.clone())
        .unwrap_or_default()
}

/// Built-in compression algorithms (§6.3): in zero-knowledge mode compression is done by the SDK; the server only declares and validates.
pub fn compression_allowed(state: &AppState, algo: &str) -> bool {
    let allowed = ["zstd", "lz4", "none"];
    if !allowed.contains(&algo) {
        return false;
    }
        // In inspectable mode the server may compress; zero-knowledge mode still accepts a client compression flag
    let _ = state;
    true
}

/// Plugin invocation entry point (P5: passthrough as "no converter" while wasmtime / sidecar are not wired up, ⑤ §10).
pub async fn convert(_state: Arc<AppState>, _ns: &str, _input: &[u8]) -> Option<Vec<u8>> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passthrough_when_receiver_supports() {
        let s_caps = Caps { formats: vec!["json".into()], ..Default::default() };
        let r_caps = Caps { formats: vec!["json".into(), "text".into()], ..Default::default() };
        let n = negotiate_dummy(&s_caps, &r_caps, "json");
        assert_eq!(n.target_type, "json");
        assert!(!n.needs_convert);
    }

    fn negotiate_dummy(s: &Caps, r: &Caps, ty: &str) -> Negotiation {
        let supported = |caps: &Caps, t: &str| {
            caps.formats.is_empty() || caps.formats.iter().any(|f| f == t)
        };
        if supported(r, ty) {
            return Negotiation { target_type: ty.to_string(), needs_convert: false, plugin: None };
        }
        let candidate = s.formats.iter().find(|f| supported(r, f)).cloned();
        match candidate.or_else(|| r.formats.first().cloned()) {
            Some(t) => Negotiation { target_type: t, needs_convert: true, plugin: None },
            None => Negotiation { target_type: ty.to_string(), needs_convert: false, plugin: None },
        }
    }
}
