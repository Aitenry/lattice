//! Local WAL: stages small messages while PG is unwritable, replaying them in order after recovery (② §4.8 degradation matrix).
//!
//! Design tradeoff: doc ② §4.8 says "disk append, zstd-compressed blocks"; this uses **line-delimited JSON + immediate fsync**
//! (no zstd dependency). Replay goes through `insert_message`, idempotency is handled by `message_dedup`,
//! so WAL replay is naturally re-entrant — exactly the "WAL replay (idempotent, via dedup)" the docs require.
//!
//! Boundaries (aligned with ② §4.8 / PL-12 12.3):
//! - **Small messages only**: payload inline, no `payload_ref`, `size ≤ 1MB`; large messages/objects never enter the WAL,
//!   and the caller returns an explicit error (silently dropping data is worse than a 500).
//! - **Bounded**: above [`Wal::max_bytes`], [`Wal::append`] returns [`AppendOutcome::Full`],
//!   and the caller must reject and increment `lattice_wal_dropped_total` (no silent unbounded growth).
//! - **WAL replays persistence only**: replay does not re-route or resend business receipts (routing/receipts already followed the online path during degradation).

use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::Result;

/// Default WAL file limit 64MiB (append is rejected above it; matches the `[wal] max_bytes` default).
pub const WAL_MAX_BYTES_DEFAULT: u64 = 64 * 1024 * 1024;

/// One pending record (**small message**: payload inline as base64).
///
/// Old/new field compatibility: new fields are always `#[serde(default)]`, so old WAL files (only id/conv/sender…)
/// remain readable; a missing `seq` (0) is rejected by PG on replay → handled as poison (never stalls the queue).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalRecord {
    pub id: String,
    pub conv_id: String,
    pub sender: String,
    pub env_type: String,
    pub content_type: Option<String>,
    pub size: i64,
    pub payload_b64: String,
    /// Per-session seq already assigned at WAL entry (replay writes it back with the original seq to avoid reordering)
    #[serde(default)]
    pub seq: i64,
    /// Original `expires_at` (millisecond timestamp); None = never expires
    #[serde(default)]
    pub expires_at_ms: Option<u64>,
    pub ttl_seconds: u32,
    /// Local time of WAL entry (used as `messages.created_at` on replay to preserve the original order)
    pub recorded_at_ms: u64,
}

impl WalRecord {
    /// Estimate serialized size in bytes (including newline) for the pre-append quota check.
    pub fn estimated_bytes(&self) -> u64 {
        // to_string fails only in extreme cases; a conservative upper bound is enough (quota checks need no precision).
        serde_json::to_vec(self).map(|v| v.len() as u64 + 1).unwrap_or(u64::MAX / 2)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppendOutcome {
    /// Appended and fsynced
    Appended,
    /// Above `max_bytes`, **not written** (the caller must reject the message and count it as dropped)
    Full,
}

#[derive(Debug, Clone)]
pub struct Wal {
    dir: PathBuf,
    max_bytes: u64,
}

impl Wal {
    /// Default limit (for old call sites/unit tests); production construction should use [`Wal::with_options`].
    pub fn new(dir: impl AsRef<Path>) -> Self {
        Self::with_options(dir, WAL_MAX_BYTES_DEFAULT)
    }

    /// `max_bytes = 0` is invalid → fall back to the default 64MiB (same semantics as `[wal] max_bytes`).
    pub fn with_options(dir: impl AsRef<Path>, max_bytes: u64) -> Self {
        Wal {
            dir: dir.as_ref().to_path_buf(),
            max_bytes: if max_bytes == 0 { WAL_MAX_BYTES_DEFAULT } else { max_bytes },
        }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn max_bytes(&self) -> u64 {
        self.max_bytes
    }

    fn file(&self) -> PathBuf {
        self.dir.join("node-wal.jsonl")
    }

    pub fn size_bytes(&self) -> u64 {
        std::fs::metadata(self.file()).map(|m| m.len()).unwrap_or(0)
    }

    /// Append one record and fsync (nothing lost after a crash).
    ///
    /// Returns [`AppendOutcome::Full`] and **writes nothing** above `max_bytes`; a WAL write failure (directory unavailable/
    /// disk read-only, etc.) returns an error that the caller propagates as a 500 (only a WAL write failure fails the send).
    pub fn append(&self, rec: &WalRecord) -> Result<AppendOutcome> {
        std::fs::create_dir_all(&self.dir).map_err(|e| {
            crate::error::internal(format!("wal dir unavailable: {e}"))
        })?;
        // Quota check: current size + this record estimate > limit → reject (including empty file; a limit smaller than one record also rejects)
        if self.size_bytes().saturating_add(rec.estimated_bytes()) > self.max_bytes {
            return Ok(AppendOutcome::Full);
        }
        let line = serde_json::to_string(rec)
            .map_err(|e| crate::error::internal(format!("wal encode failed: {e}")))?;
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.file())
            .map_err(|e| crate::error::internal(format!("wal open failed: {e}")))?;
        f.write_all(line.as_bytes())
            .and_then(|_| f.write_all(b"\n"))
            .and_then(|_| f.sync_all())
            .map_err(|e| crate::error::internal(format!("wal write failed: {e}")))?;
        Ok(AppendOutcome::Appended)
    }

    /// Read all records (the caller `clear`s / `replace`s after replay).
    pub fn read_all(&self) -> Result<Vec<WalRecord>> {
        let path = self.file();
        if !path.exists() {
            return Ok(Vec::new());
        }
        let raw = std::fs::read_to_string(&path)
            .map_err(|e| crate::error::internal(format!("wal read failed: {e}")))?;
        let mut out = Vec::new();
        for line in raw.lines() {
            if line.trim().is_empty() {
                continue;
            }
            match serde_json::from_str::<WalRecord>(line) {
                Ok(r) => out.push(r),
                Err(e) => tracing::warn!(error = %e, "skip corrupt wal line"),
            }
        }
        Ok(out)
    }

    /// Keep unreplayed records after a partial replay: rewrite atomically (temp file + fsync + rename); empty is equivalent to clear.
    ///
    /// Needed only when replay has both permanent failures (poison) and transient failures; other paths use
    /// [`Wal::clear`] (all succeeded) or keep the original file (transient failures, retry next round, duplicates covered by dedup).
    pub fn replace(&self, records: &[WalRecord]) -> Result<()> {
        if records.is_empty() {
            return self.clear();
        }
        std::fs::create_dir_all(&self.dir).map_err(|e| {
            crate::error::internal(format!("wal dir unavailable: {e}"))
        })?;
        let tmp = self.dir.join("node-wal.jsonl.tmp");
        let mut body = String::new();
        for rec in records {
            let line = serde_json::to_string(rec)
                .map_err(|e| crate::error::internal(format!("wal encode failed: {e}")))?;
            body.push_str(&line);
            body.push('\n');
        }
        {
            let mut f = std::fs::File::create(&tmp)
                .map_err(|e| crate::error::internal(format!("wal tmp create failed: {e}")))?;
            f.write_all(body.as_bytes())
                .and_then(|_| f.sync_all())
                .map_err(|e| crate::error::internal(format!("wal tmp write failed: {e}")))?;
        }
        let path = self.file();
        // Windows rename does not overwrite an existing file; delete the target before renaming (across a crash window, retained files are lost,
        // but they are all "not yet replayed" records → an observable failure on par with WAL file corruption, and logged as an error).
        if cfg!(windows) && path.exists() {
            let _ = std::fs::remove_file(&path);
        }
        std::fs::rename(&tmp, &path)
            .map_err(|e| crate::error::internal(format!("wal replace failed: {e}")))?;
        Ok(())
    }

    pub fn clear(&self) -> Result<()> {
        let path = self.file();
        if path.exists() {
            std::fs::remove_file(&path)
                .map_err(|e| crate::error::internal(format!("wal clear failed: {e}")))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(id: &str, payload: &[u8]) -> WalRecord {
        WalRecord {
            id: id.into(),
            conv_id: "01H".into(),
            sender: "01G".into(),
            env_type: "text".into(),
            content_type: Some("text/plain".into()),
            size: payload.len() as i64,
            payload_b64: lattice_core::envelope::base64_encode(payload),
            seq: 1,
            expires_at_ms: None,
            ttl_seconds: 0,
            recorded_at_ms: 1,
        }
    }

    fn tmp_dir(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "lattice-wal-test-{}-{tag}-{}",
            std::process::id(),
            // Concurrent tests in one process: use a unique suffix other than thread id (nanoseconds) to avoid mutual cleanup
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ))
    }

    #[test]
    fn append_read_clear() {
        let dir = tmp_dir("append");
        let wal = Wal::new(&dir);
        let _ = wal.clear();
        let r = rec("01J", b"hello");
        assert_eq!(wal.append(&r).unwrap(), AppendOutcome::Appended);
        assert_eq!(wal.append(&r).unwrap(), AppendOutcome::Appended);
        let all = wal.read_all().unwrap();
        assert_eq!(all.len(), 2);
        assert!(wal.size_bytes() > 0);
        wal.clear().unwrap();
        assert!(wal.read_all().unwrap().is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn append_refuses_after_max_bytes() {
        // Limit set very small: the first record does not fit → Full and no file appears (no silent unbounded growth)
        let dir = tmp_dir("full");
        let wal = Wal::with_options(&dir, 32);
        let small = rec("01J", b"hello");
        assert!(small.estimated_bytes() > 32);
        assert_eq!(wal.append(&small).unwrap(), AppendOutcome::Full);
        assert_eq!(wal.size_bytes(), 0);
        assert!(wal.read_all().unwrap().is_empty());

        // Limit fits one record but not two → first Appended, second Full, file keeps the first
        let one = rec("01J", b"x");
        let limit = one.estimated_bytes() * 2 - 1;
        let dir2 = tmp_dir("full2");
        let wal2 = Wal::with_options(&dir2, limit);
        assert_eq!(wal2.append(&one).unwrap(), AppendOutcome::Appended);
        assert_eq!(wal2.append(&one).unwrap(), AppendOutcome::Full);
        assert_eq!(wal2.read_all().unwrap().len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&dir2);
    }

    #[test]
    fn replace_keeps_only_pending_records() {
        let dir = tmp_dir("replace");
        let wal = Wal::new(&dir);
        for i in 0..3 {
            wal.append(&rec(&format!("01J{i}"), b"payload")).unwrap();
        }
        assert_eq!(wal.read_all().unwrap().len(), 3);
        // Partial replay: first two replayed/poison, keep only the last
        let all = wal.read_all().unwrap();
        wal.replace(&all[2..]).unwrap();
        let kept = wal.read_all().unwrap();
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].id, "01J2");
        // Empty replace = clear
        wal.replace(&[]).unwrap();
        assert!(wal.read_all().unwrap().is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn zero_max_bytes_falls_back_to_default() {
        assert_eq!(
            Wal::with_options(std::env::temp_dir(), 0).max_bytes(),
            WAL_MAX_BYTES_DEFAULT
        );
    }

    #[test]
    fn append_surfaces_io_error_when_dir_unusable() {
        // The directory path is occupied by a **regular file** → create_dir_all fails → append returns Err (caller turns it into 500);
        // this is the only path where "only a WAL write failure fails the send".
        let dir = tmp_dir("baddir");
        std::fs::create_dir_all(&dir).unwrap();
        let blocker = dir.join("blocker-file");
        std::fs::write(&blocker, b"x").unwrap();
        let wal = Wal::with_options(&blocker, WAL_MAX_BYTES_DEFAULT);
        let err = wal.append(&rec("01J", b"hello")).unwrap_err();
        assert!(err.to_string().contains("wal dir unavailable"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
