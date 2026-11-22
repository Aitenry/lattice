//! Pipeline stage abstraction (② §2.2).
//!
//! Uplink order: `decode → auth → validate → dedup → detect → format → seq → policy → persist → route → ack`
//! Each stage emits its own metrics and can be bypassed via `config.pipeline.bypass` (emergency). The `Stage` trait fixes the shape;
//! orchestration lives in [`crate::pipeline::ingest`], and each stage implementation lives in a submodule of this directory.

use async_trait::async_trait;

use crate::error::LatticeError;

/// Stage context: the envelope and decision results carried across stages.
pub struct Ctx {
    pub envelope: lattice_core::Envelope,
    /// Authenticated principal (injected by the server; any client-supplied value is ignored, ⑤ §4.1)
    pub sender: String,
    pub device: String,
    pub conv_id: String,
    pub seq: u64,
    pub recipients: Vec<Recipient>,
    pub dropped: bool,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct Recipient {
    pub user: String,
    pub device: String,
    pub state: String,
}

pub enum StageResult {
    /// Continue to the next stage
    Next,
    /// Stop early (e.g. reply ack directly for a duplicate message)
    Stop,
}

#[async_trait]
pub trait Stage: Send + Sync {
    const NAME: &'static str;
    async fn handle(&self, ctx: &mut Ctx) -> Result<StageResult, LatticeError>;
}

/// Error classification (② §2.2): retryable (back off before dead-lettering) vs fatal (reply an error frame + audit).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorClass {
    Retryable,
    Fatal,
}

pub fn classify(err: &LatticeError) -> ErrorClass {
    use lattice_core::ErrorCode::*;
    match err.code {
        Rate | Internal | Quota => ErrorClass::Retryable,
        _ => ErrorClass::Fatal,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_classification() {
        assert_eq!(
            classify(&LatticeError::rate("x")),
            ErrorClass::Retryable
        );
        assert_eq!(
            classify(&LatticeError::format("x")),
            ErrorClass::Fatal
        );
        assert_eq!(
            classify(&LatticeError::internal("x")),
            ErrorClass::Retryable
        );
    }
}
