//! Client plugin center (single source of truth for the contract: doc ⑤ §12; data structures: doc ⑥ §2.3; values: design §17.16).
//!
//! **Unrelated** to the admin format plugins (`plugins` table): this distributes third-party plugin packages for the desktop
//! client (RytenBench); the platform never executes package code, it only handles "ownership + storage + versions + install records/data".
//!
//! Trust boundaries (② §4.9):
//! ① only owner/admin can add versions or unpublish; ② downloaders verify integrity via the metadata sha256;
//! ③ the installer performs in-package validation (entry file, path traversal rejection). The server validates **structure** only (zip + plugin.json).

use std::cmp::Ordering;
use std::sync::Arc;

use axum::body::{Body, Bytes};
use axum::extract::{DefaultBodyLimit, Path, Query, Request, State};
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, put};
use axum::{Json, Router};
use futures::StreamExt;
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::auth::rbac::AuthUser;
use crate::error::{self, ApiErr, ApiResult, LatticeError};
use crate::state::AppState;
use crate::store::pg::{self, HubDraftError, HubDraftOutcome, HubInstallOutcome, HubNewVersion};

// ---------------------------------------------------------------------------
// Values from design §17.16 (referenced here, not redefined)
// ---------------------------------------------------------------------------

/// Plugin package cap 20MiB (§17.16).
pub const MAX_PACKAGE_BYTES: usize = 20 * 1024 * 1024;
/// Version source package (optional) cap 50MiB (v2 contract §1.1 / §17.16).
pub const MAX_SOURCE_BYTES: usize = 50 * 1024 * 1024;
/// Cap for the decompressed `plugin.json` inside a source package (zip-bomb protection; normal manifests are far smaller).
const MAX_SOURCE_MANIFEST_BYTES: usize = 1024 * 1024;
/// Plugin data snapshot cap 256KiB (§17.16).
pub const MAX_DATA_BYTES: usize = 256 * 1024;
const MAX_NAME: usize = 64;
const MAX_DESCRIPTION: usize = 500;
const MAX_README: usize = 16 * 1024;
const MAX_ICON: usize = 512;
const MAX_CHANGELOG: usize = 2000;
const MAX_MANIFEST: usize = 16 * 1024;
const MAX_TAGS: usize = 8;
const MAX_TAG: usize = 24;
const PRESIGN_TTL_SECS: u64 = 900;
const DRAFT_TTL_SECS: u64 = 30 * 60;

const CATEGORIES: [&str; 6] = ["productivity", "ai", "media", "devtools", "data", "other"];
const SORTS: [&str; 3] = ["recent", "popular", "name"];

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/v1/hub/plugins", get(list).post(create))
        .route("/v1/hub/plugins/:plugin_id", get(detail).delete(delete_plugin))
        .route(
            "/v1/hub/plugins/:plugin_id/versions/:version",
            axum::routing::delete(delete_version),
        )
        .route(
            "/v1/hub/plugins/:plugin_id/versions/:version/blob",
            put(upload_blob)
                .layer(DefaultBodyLimit::max(MAX_PACKAGE_BYTES + 64 * 1024))
                .layer(axum::middleware::from_fn(package_body_guard)),
        )
        .route(
            "/v1/hub/plugins/:plugin_id/versions/:version/download",
            get(download),
        )
        .route(
            "/v1/hub/plugins/:plugin_id/versions/:version/source",
            get(download_source)
                .put(upload_source)
                .layer(DefaultBodyLimit::max(MAX_SOURCE_BYTES + 64 * 1024))
                .layer(axum::middleware::from_fn(source_body_guard)),
        )
        .route(
            "/v1/hub/installs",
            get(list_installs),
        )
        .route(
            "/v1/hub/installs/:plugin_id",
            put(upsert_install).delete(delete_install),
        )
        .route("/v1/hub/stats", get(stats))
}

/// Upload body limit guard: checks `Content-Length` before buffering the body, returning a ⑤ §0.5 error body.
/// (Same lesson as `/v1/messages`, ② §3.1: a framework-level body-limit alone drops `code`/`details`.)
async fn package_body_guard(req: Request, next: Next) -> Response {
    if let Some(len) = req
        .headers()
        .get("content-length")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
    {
        if len > MAX_PACKAGE_BYTES as u64 {
            let e = LatticeError::too_large(format!(
                "package body {len} bytes exceeds {MAX_PACKAGE_BYTES}"
            ))
            .with_reason("hub_package")
            .with_detail("max_bytes", json!(MAX_PACKAGE_BYTES));
            return ApiErr(e).into_response();
        }
    }
    next.run(req).await
}

/// Source package upload body limit guard (v2 contract §1.3: ≤50MiB; over the limit → `413 TOO_LARGE`).
///
/// Same rationale as [`package_body_guard`]: when `DefaultBodyLimit` rejects in the extractor stage,
/// axum emits a plain-text 413 and the client gets no `code`/`details.reason`; here, **before streaming**,
/// we check `Content-Length` and return the structured ⑤ §0.5 error body.
/// Without `Content-Length` (chunked), [`upload_source`] counts bytes as it reads.
async fn source_body_guard(req: Request, next: Next) -> Response {
    if let Some(len) = req
        .headers()
        .get("content-length")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
    {
        if len > MAX_SOURCE_BYTES as u64 {
            let e = LatticeError::too_large(format!(
                "source archive body {len} bytes exceeds {MAX_SOURCE_BYTES}"
            ))
            .with_reason("hub_source")
            .with_detail("max_bytes", json!(MAX_SOURCE_BYTES));
            return ApiErr(e).into_response();
        }
    }
    next.run(req).await
}

// ---------------------------------------------------------------------------
// §12.1 list / §12.2 detail
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct CatalogQuery {
    q: Option<String>,
    category: Option<String>,
    sort: Option<String>,
    page: Option<i64>,
    page_size: Option<i64>,
}

async fn list(
    State(st): State<Arc<AppState>>,
    user: AuthUser,
    Query(q): Query<CatalogQuery>,
) -> ApiResult<Response> {
    user.require_read()?;
    let page = q.page.unwrap_or(1).max(1);
    let page_size = q.page_size.unwrap_or(20).clamp(1, 100);
    let sort = q.sort.unwrap_or_else(|| "recent".into());
    if !SORTS.contains(&sort.as_str()) {
        return Err(ApiErr(
            LatticeError::format("invalid sort").with_reason("sort").with_detail("field", json!("sort")),
        ));
    }
    let category = q.category.unwrap_or_default();
    if !category.is_empty() && !CATEGORIES.contains(&category.as_str()) {
        return Err(ApiErr(
            LatticeError::format("invalid category")
                .with_reason("category")
                .with_detail("field", json!("category")),
        ));
    }
    let search = q.q.unwrap_or_default().trim().to_string();
    let (rows, total) = pg::hub_catalog(
        &st.db,
        &user.user_id,
        &search,
        &category,
        &sort,
        page_size,
        (page - 1) * page_size,
    )
    .await?;

    let items: Vec<Value> = rows
        .iter()
        .map(|r| {
            json!({
                "plugin_id": r.plugin_id,
                "name": r.name,
                "description": r.description,
                "icon": r.icon,
                "category": r.category,
                "tags": r.tags,
                "owner": {
                    "id": r.owner_id,
                    "username": r.owner_username,
                    "display_name": r.owner_display_name,
                },
                "latest_version": r.latest_version,
                "size": r.latest_size,
                "has_source": r.latest_has_source.unwrap_or(false),
                "downloads": r.downloads,
                "versions_count": r.versions_count,
                "updated_at": r.updated_at,
                "installed": r.installed_version.is_some(),
                "installed_version": r.installed_version,
                // Only a **higher** platform version counts as updatable: with local 1.1.7 and platform 1.1.6, "any difference means update"
                // would label downgrades as updates (both the console and RytenBench would show "update to an older version").
                "update_available": matches!(
                    (&r.installed_version, &r.latest_version),
                    (Some(i), Some(l)) if compare_semver(l, i) == std::cmp::Ordering::Greater
                ),
                "install_enabled": r.install_enabled,
            })
        })
        .collect();
    Ok(Json(json!({
        "items": items, "total": total, "page": page, "page_size": page_size
    }))
    .into_response())
}

async fn detail(
    State(st): State<Arc<AppState>>,
    user: AuthUser,
    Path(plugin_id): Path<String>,
) -> ApiResult<Response> {
    let plugin = load_visible_plugin(&st, &user, &plugin_id).await?;
    let versions = pg::hub_versions_of(&st.db, &plugin.id, false).await?;
    let install = pg::hub_install_of(&st.db, &user.user_id, &plugin_id).await?;

    let version_items: Vec<Value> = versions
        .iter()
        .map(|v| {
            json!({
                "version": v.version,
                "asset_name": v.asset_name,
                "size": v.size,
                "sha256": v.sha256,
                "changelog": v.changelog,
                "manifest": v.manifest,
                "downloads": v.downloads,
                "published_at": v.published_at,
                "has_source": v.source_object_key.is_some(),
                "source_asset_name": v.source_asset_name,
                "source_size": v.source_size,
                "source_sha256": v.source_sha256,
            })
        })
        .collect();
    Ok(Json(json!({
        "plugin_id": plugin.plugin_id,
        "name": plugin.name,
        "description": plugin.description,
        "readme": plugin.readme,
        "icon": plugin.icon,
        "category": plugin.category,
        "tags": plugin.tags,
        "owner": {
            "id": plugin.owner_id,
            "username": plugin.owner_username,
            "display_name": plugin.owner_display_name,
        },
        "latest_version": plugin.latest_version,
        "downloads": plugin.downloads,
        "created_at": plugin.created_at,
        "updated_at": plugin.updated_at,
        "versions": version_items,
        "my_install": install.map(|i| json!({
            "version": i.version, "enabled": i.enabled,
            "data_rev": i.data_rev, "data_updated_at": i.data_updated_at,
        })),
    }))
    .into_response())
}

async fn load_visible_plugin(
    st: &Arc<AppState>,
    user: &AuthUser,
    plugin_id: &str,
) -> ApiResult<pg::HubPluginRow> {
    let plugin = pg::hub_plugin_by_plugin_id(&st.db, plugin_id)
        .await?
        .ok_or_else(|| ApiErr(LatticeError::not_found("plugin not found")))?;
    let visible =
        plugin.status == "published" || plugin.owner_id == user.user_id || user.is_admin();
    if !visible {
        return Err(ApiErr(LatticeError::not_found("plugin not found")));
    }
    Ok(plugin)
}

// ---------------------------------------------------------------------------
// §12.3 publish (metadata) / §12.4 upload package body
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct CreateReq {
    plugin_id: String,
    version: String,
    name: String,
    #[serde(default)]
    description: String,
    readme: Option<String>,
    icon: Option<String>,
    category: Option<String>,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    changelog: String,
    asset_name: String,
    size: i64,
    sha256: String,
    manifest: Value,
    /// v2 contract §1.2: optional source package declaration (`None` = no source for this version)
    source: Option<SourceMetaReq>,
}

/// Optional `source{}` in `POST /v1/hub/plugins` (v2 contract §1.2).
#[derive(Debug, Clone, Deserialize)]
struct SourceMetaReq {
    asset_name: String,
    size: i64,
    sha256: String,
}

async fn create(
    State(st): State<Arc<AppState>>,
    user: AuthUser,
    Json(req): Json<CreateReq>,
) -> ApiResult<Response> {
    rate_limit(&st, "publish", &user.user_id, 3600, 10, "hub_publish").await?;
    validate_create(&req)?;

    let category = req.category.clone().unwrap_or_else(|| "other".into());
    let readme = req.readme.as_deref();
    let icon = req.icon.as_deref();
    let object_key = format!("{}/{}/{}", req.plugin_id, req.version, req.asset_name);
    let draft = HubNewVersion {
        plugin_id: &req.plugin_id,
        name: req.name.trim(),
        description: req.description.trim(),
        readme,
        icon,
        category: &category,
        tags: &req.tags,
        version: &req.version,
        changelog: req.changelog.trim(),
        asset_name: &req.asset_name,
        size: req.size,
        sha256: &req.sha256,
        object_key: &object_key,
        manifest: &req.manifest,
        source_asset_name: req.source.as_ref().map(|s| s.asset_name.as_str()),
        source_size: req.source.as_ref().map(|s| s.size),
        source_sha256: req.source.as_ref().map(|s| s.sha256.as_str()),
    };

    match pg::hub_create_draft(&st.db, &user.user_id, user.is_admin(), &draft).await {
        Ok(HubDraftOutcome::Draft { plugin, version, reused }) => {
            audit(
                &st,
                &user,
                "hub.plugin.create",
                &req.plugin_id,
                json!({ "version": req.version, "size": req.size }),
            )
            .await;
            let status = if reused { StatusCode::OK } else { StatusCode::CREATED };
            let source_upload = source_upload_of(&req.plugin_id, &version);
            Ok((
                status,
                Json(json!({
                    "plugin": plugin_json(&plugin),
                    "version": version_json(&version),
                    "upload": {
                        "method": "PUT",
                        "path": format!(
                            "/v1/hub/plugins/{}/versions/{}/blob",
                            req.plugin_id, req.version
                        ),
                        "headers": {
                            "Content-Type": "application/octet-stream",
                            "X-Content-SHA256": req.sha256,
                        },
                        "max_bytes": MAX_PACKAGE_BYTES,
                        "expires_at": chrono::Utc::now()
                            + chrono::Duration::seconds(DRAFT_TTL_SECS as i64),
                    },
                    "source_upload": source_upload,
                    "idempotent_reused": reused,
                })),
            )
                .into_response())
        }
        Ok(HubDraftOutcome::AlreadyPublished { plugin, version }) => {
            let source_upload = source_upload_of(&req.plugin_id, &version);
            Ok(Json(json!({
                "plugin": plugin_json(&plugin),
                "version": version_json(&version),
                "upload": null,
                "source_upload": source_upload,
                "idempotent": true,
            }))
            .into_response())
        }
        Err(HubDraftError::NotOwner) => Err(ApiErr(
            LatticeError::forbidden("only the owner can publish a new version").with_reason("not_owner"),
        )),
        Err(HubDraftError::VersionPublished { sha256 }) => Err(ApiErr(
            LatticeError::conflict("version already published with a different package")
                .with_reason("version_published")
                .with_detail("published_sha256", json!(sha256)),
        )),
        Err(HubDraftError::Db(e)) => Err(ApiErr(error::db(e))),
    }
}

async fn upload_blob(
    State(st): State<Arc<AppState>>,
    user: AuthUser,
    Path((plugin_id, version)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Response> {
    rate_limit(&st, "upload", &user.user_id, 3600, 60, "hub_upload").await?;
    let plugin = load_visible_plugin(&st, &user, &plugin_id).await?;
    if plugin.owner_id != user.user_id && !user.is_admin() {
        return Err(ApiErr(
            LatticeError::forbidden("only the owner can upload a package").with_reason("not_owner"),
        ));
    }
    let row = pg::hub_version(&st.db, &plugin.id, &version)
        .await?
        .ok_or_else(|| ApiErr(LatticeError::not_found("plugin version not found")))?;
    if row.status == "removed" {
        // An unpublished version must not be revived via the same path: restoring requires publishing a new version (⑤ §12.6)
        return Err(ApiErr(LatticeError::not_found("plugin version not found")));
    }

    let declared = header_str(&headers, "x-content-sha256").unwrap_or_default();
    if declared.is_empty() {
        return Err(ApiErr(
            LatticeError::format("missing X-Content-SHA256").with_reason("checksum"),
        ));
    }
    if !declared.eq_ignore_ascii_case(&row.sha256) {
        return Err(ApiErr(
            LatticeError::format("X-Content-SHA256 does not match the published metadata")
                .with_reason("checksum"),
        ));
    }
    if body.len() > MAX_PACKAGE_BYTES {
        return Err(ApiErr(
            LatticeError::too_large("package exceeds 20MiB")
                .with_reason("hub_package")
                .with_detail("max_bytes", json!(MAX_PACKAGE_BYTES)),
        ));
    }
    if body.len() as i64 != row.size {
        return Err(ApiErr(
            LatticeError::format("package size differs from the declared size")
                .with_reason("size")
                .with_detail("declared", json!(row.size))
                .with_detail("received", json!(body.len())),
        ));
    }

    let digest = hex_lower(&Sha256::digest(&body));
    if digest != row.sha256 {
        return Err(ApiErr(
            LatticeError::format("sha256 mismatch").with_reason("checksum"),
        ));
    }
    if let Err(reason) = validate_package(&body) {
        return Err(ApiErr(
            LatticeError::format(format!("invalid plugin package: {reason}"))
                .with_reason("package")
                .with_detail("detail", json!(reason)),
        ));
    }

    if row.status == "published" {
        // Already published with the same sha: the upload is an idempotent retry, do not store the object again (⑤ §12.4)
        return Ok(Json(json!({
            "plugin_id": plugin_id, "version": version, "status": "published",
            "sha256": row.sha256, "size": row.size, "published_at": row.published_at,
            "download_path": download_path(&plugin_id, &version),
            "idempotent": true,
        }))
        .into_response());
    }

    let bucket = st.s3.cfg().bucket_plugins.clone();
    st.s3
        .put_bytes(&bucket, &row.object_key, &body)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "hub package upload to s3 failed");
            ApiErr(
                LatticeError::internal("object storage unavailable")
                    .with_detail("dep", json!("s3")),
            )
        })?;

    let published = pg::hub_publish_version(&st.db, &row.id)
        .await?
        .ok_or_else(|| ApiErr(LatticeError::not_found("plugin version not found")))?;
    audit(
        &st,
        &user,
        "hub.version.publish",
        &plugin_id,
        json!({ "version": version, "size": published.size, "sha256": published.sha256 }),
    )
    .await;

    Ok(Json(json!({
        "plugin_id": plugin_id,
        "version": version,
        "status": published.status,
        "sha256": published.sha256,
        "size": published.size,
        "published_at": published.published_at,
        "download_path": download_path(&plugin_id, &version),
    }))
    .into_response())
}

// ---------------------------------------------------------------------------
// §12.4 (v2 contract §1.3/§1.4) source package upload / download
// ---------------------------------------------------------------------------

/// Decision result for a source package PUT (pure function for unit testing; the actual persistence decision still happens in
/// [`pg::hub_set_source`]'s `for update` transaction to prevent concurrent double writes).
#[derive(Debug, PartialEq, Eq)]
enum SourcePutDecision {
    /// No source package declared at POST time (no source for this version)
    NotDeclared,
    /// Source exists with a different sha: changing source requires a new version
    Conflict { published_sha256: String },
    /// Same sha already uploaded: idempotent retry
    Idempotent,
    /// Declared but not yet uploaded, and the request header does not match the declared value
    ChecksumMismatch,
    /// Declared, not yet uploaded, and checksums match: may write the object
    Proceed,
}

/// Three-way comparison for source upload: `sha declared at POST`, `sha of the uploaded object`, `sha in this request header`.
fn decide_source_put(
    declared_sha: Option<&str>,
    stored_sha: Option<&str>,
    header_sha: &str,
) -> SourcePutDecision {
    match stored_sha {
        Some(stored) if stored.eq_ignore_ascii_case(header_sha) => SourcePutDecision::Idempotent,
        Some(stored) => SourcePutDecision::Conflict { published_sha256: stored.to_string() },
        None => match declared_sha {
            None => SourcePutDecision::NotDeclared,
            Some(declared) if declared.eq_ignore_ascii_case(header_sha) => {
                SourcePutDecision::Proceed
            }
            Some(_) => SourcePutDecision::ChecksumMismatch,
        },
    }
}

/// Hash while reading: stream the body into `Vec<u8>` while incrementally computing SHA-256, truncating at 50MiB
/// **during the read** (for chunked requests without `Content-Length`, [`source_body_guard`] cannot intercept).
async fn read_source_body(body: Body) -> ApiResult<(Vec<u8>, String)> {
    let mut stream = body.into_data_stream();
    let mut hasher = Sha256::new();
    let mut out: Vec<u8> = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| {
            ApiErr(
                LatticeError::format(format!("failed to read source archive body: {e}"))
                    .with_reason("body"),
            )
        })?;
        if out.len() + chunk.len() > MAX_SOURCE_BYTES {
            return Err(ApiErr(
                LatticeError::too_large(format!(
                    "source archive exceeds {} bytes",
                    MAX_SOURCE_BYTES
                ))
                .with_reason("hub_source")
                .with_detail("max_bytes", json!(MAX_SOURCE_BYTES)),
            ));
        }
        hasher.update(&chunk);
        out.extend_from_slice(&chunk);
    }
    let digest = hex_lower(&hasher.finalize());
    Ok((out, digest))
}

/// `PUT /v1/hub/plugins/{plugin_id}/versions/{version}/source` (v2 contract §1.3).
///
/// Idempotent: same sha already uploaded → 200; source exists with a different sha → 409 `source_published`.
/// May be called at any time before or after package upload; source visibility still depends on the package being `published`.
async fn upload_source(
    State(st): State<Arc<AppState>>,
    user: AuthUser,
    Path((plugin_id, version)): Path<(String, String)>,
    headers: HeaderMap,
    body: Body,
) -> ApiResult<Response> {
    rate_limit(&st, "source", &user.user_id, 3600, 60, "hub_source").await?;
    let plugin = load_visible_plugin(&st, &user, &plugin_id).await?;
    require_owner(&user, &plugin)?;
    let row = pg::hub_version(&st.db, &plugin.id, &version)
        .await?
        .ok_or_else(|| ApiErr(LatticeError::not_found("plugin version not found")))?;
    if row.status == "removed" {
        // An unpublished version must not be revived via the same path (same rule as package upload, ⑤ §12.6)
        return Err(ApiErr(LatticeError::not_found("plugin version not found")));
    }

    let header_sha = header_str(&headers, "x-content-sha256")
        .unwrap_or_default()
        .to_ascii_lowercase();
    if header_sha.is_empty() {
        return Err(ApiErr(
            LatticeError::format("missing X-Content-SHA256").with_reason("checksum"),
        ));
    }

    let stored_sha = if row.source_object_key.is_some() {
        row.source_sha256.as_deref()
    } else {
        None
    };
    let decision = decide_source_put(row.source_sha256.as_deref(), stored_sha, &header_sha);

    if row.source_object_key.is_some() {
        return match decision {
            SourcePutDecision::Idempotent => {
                // Re-upload with the same sha: still read the whole body and re-verify, so "declaration matches but bytes are corrupt" does not return 200.
                let (bytes, digest) = read_source_body(body).await?;
                let declared_size = row.source_size.unwrap_or(0);
                if bytes.len() as i64 != declared_size {
                    return Err(ApiErr(
                        LatticeError::format("source archive size differs from the declared size")
                            .with_reason("size")
                            .with_detail("declared", json!(declared_size))
                            .with_detail("received", json!(bytes.len())),
                    ));
                }
                if !digest.eq_ignore_ascii_case(row.source_sha256.as_deref().unwrap_or_default()) {
                    return Err(ApiErr(
                        LatticeError::format("sha256 mismatch").with_reason("checksum"),
                    ));
                }
                Ok(Json(source_json(&plugin_id, &row, true)).into_response())
            }
            SourcePutDecision::Conflict { published_sha256 } => Err(ApiErr(
                LatticeError::conflict("a different source archive is already published for this version")
                    .with_reason("source_published")
                    .with_detail("published_sha256", json!(published_sha256)),
            )),
            // When stored_sha is Some, branches other than the two above are impossible
            _ => Err(ApiErr(LatticeError::internal("unexpected source upload state"))),
        };
    }

    let (source_asset_name, declared_size, declared_sha) = (
        row.source_asset_name.clone(),
        row.source_size,
        row.source_sha256.clone(),
    );
    match decision {
        SourcePutDecision::NotDeclared => Err(ApiErr(
            LatticeError::format(
                "this version has no source archive declared; declare `source` when publishing",
            )
            .with_reason("source_not_declared"),
        )),
        SourcePutDecision::ChecksumMismatch => Err(ApiErr(
            LatticeError::format("X-Content-SHA256 does not match the declared source metadata")
                .with_reason("checksum"),
        )),
        SourcePutDecision::Proceed => {
            let (Some(asset_name), Some(declared_size), Some(declared_sha)) =
                (source_asset_name, declared_size, declared_sha)
            else {
                return Err(ApiErr(
                    LatticeError::internal("incomplete source metadata on version row")
                        .with_detail("dep", json!("pg")),
                ));
            };
            let (bytes, digest) = read_source_body(body).await?;
            if bytes.len() as i64 != declared_size {
                return Err(ApiErr(
                    LatticeError::format("source archive size differs from the declared size")
                        .with_reason("size")
                        .with_detail("declared", json!(declared_size))
                        .with_detail("received", json!(bytes.len())),
                ));
            }
            if digest != declared_sha {
                return Err(ApiErr(
                    LatticeError::format("sha256 mismatch").with_reason("checksum"),
                ));
            }
            if let Err(reason) = validate_source_package(&bytes, &plugin_id) {
                return Err(ApiErr(
                    LatticeError::format(format!("invalid source archive: {reason}"))
                        .with_reason("package")
                        .with_detail("detail", json!(reason)),
                ));
            }
            let object_key = source_object_key(&plugin_id, &version, &asset_name);
            let bucket = st.s3.cfg().bucket_plugins.clone();
            st.s3
                .put_bytes(&bucket, &object_key, &bytes)
                .await
                .map_err(|e| {
                    tracing::error!(error = %e, "hub source upload to s3 failed");
                    ApiErr(
                        LatticeError::internal("object storage unavailable")
                            .with_detail("dep", json!("s3")),
                    )
                })?;
            match pg::hub_set_source(
                &st.db,
                &row.id,
                &asset_name,
                declared_size,
                &declared_sha,
                &object_key,
            )
            .await?
            {
                pg::HubSetSourceOutcome::Stored => {
                    audit(
                        &st,
                        &user,
                        "hub.version.source",
                        &plugin_id,
                        json!({
                            "version": version,
                            "source_asset_name": asset_name,
                            "source_size": declared_size,
                            "source_sha256": declared_sha,
                        }),
                    )
                    .await;
                    let mut fresh = row;
                    fresh.source_asset_name = Some(asset_name);
                    fresh.source_size = Some(declared_size);
                    fresh.source_sha256 = Some(declared_sha);
                    fresh.source_object_key = Some(object_key);
                    Ok(Json(source_json(&plugin_id, &fresh, false)).into_response())
                }
                // Under concurrency another request already wrote the same sha: equivalent to an idempotent retry
                pg::HubSetSourceOutcome::Idempotent => {
                    Ok(Json(source_json(&plugin_id, &row, true)).into_response())
                }
                pg::HubSetSourceOutcome::Conflict { published_sha256 } => Err(ApiErr(
                    LatticeError::conflict(
                        "a different source archive is already published for this version",
                    )
                    .with_reason("source_published")
                    .with_detail("published_sha256", json!(published_sha256)),
                )),
                pg::HubSetSourceOutcome::NotFound => {
                    Err(ApiErr(LatticeError::not_found("plugin version not found")))
                }
            }
        }
        SourcePutDecision::Idempotent | SourcePutDecision::Conflict { .. } => {
            // Unreachable when source_object_key is empty (the decision is derived only from declared)
            Err(ApiErr(LatticeError::internal("unexpected source upload state")))
        }
    }
}

/// Visibility decision for source download (same conventions as package download: the version must be `published`).
#[derive(Debug, PartialEq, Eq)]
enum SourceDownloadDecision {
    Downloadable,
    /// Version missing / unpublished / removed: always 404, never leak pending drafts
    VersionNotFound,
    /// Version published but has no source package
    MissingSource,
}

fn decide_source_download(status: &str, has_source: bool) -> SourceDownloadDecision {
    if status != "published" {
        SourceDownloadDecision::VersionNotFound
    } else if !has_source {
        SourceDownloadDecision::MissingSource
    } else {
        SourceDownloadDecision::Downloadable
    }
}

/// `GET /v1/hub/plugins/{plugin_id}/versions/{version}/source` (v2 contract §1.4).
///
/// Same visibility as package download: the version must be `published` (source upload does not affect version visibility);
/// no source → 404 `source_missing`; source present → 302 presigned GET.
/// Does not increment `downloads`: statistics count package downloads only; source downloads are excluded (⑤ §12.8).
async fn download_source(
    State(st): State<Arc<AppState>>,
    user: AuthUser,
    Path((plugin_id, version)): Path<(String, String)>,
) -> ApiResult<Response> {
    let plugin = load_visible_plugin(&st, &user, &plugin_id).await?;
    let row = pg::hub_version(&st.db, &plugin.id, &version)
        .await?
        .ok_or_else(|| ApiErr(LatticeError::not_found("plugin version not found")))?;
    match decide_source_download(&row.status, row.source_object_key.is_some()) {
        SourceDownloadDecision::VersionNotFound => {
            Err(ApiErr(LatticeError::not_found("plugin version not found")))
        }
        SourceDownloadDecision::MissingSource => Err(ApiErr(
            LatticeError::not_found("source archive not found").with_reason("source_missing"),
        )),
        SourceDownloadDecision::Downloadable => {
            let (Some(object_key), Some(size), Some(sha256)) = (
                row.source_object_key.clone(),
                row.source_size,
                row.source_sha256.clone(),
            ) else {
                return Err(ApiErr(
                    LatticeError::internal("incomplete source metadata on version row")
                        .with_detail("dep", json!("pg")),
                ));
            };
            let bucket = st.s3.cfg().bucket_plugins.clone();
            let url = st.s3.presign_get(&bucket, &object_key, PRESIGN_TTL_SECS);

            let mut resp = StatusCode::FOUND.into_response();
            resp.headers_mut().insert(
                axum::http::header::LOCATION,
                axum::http::HeaderValue::from_str(&url)
                    .map_err(|_| ApiErr(LatticeError::internal("bad presigned url")))?,
            );
            resp.headers_mut().insert(
                axum::http::HeaderName::from_static("x-content-sha256"),
                axum::http::HeaderValue::from_str(&sha256)
                    .map_err(|_| ApiErr(LatticeError::internal("bad sha256")))?,
            );
            resp.headers_mut().insert(
                axum::http::HeaderName::from_static("x-content-length"),
                axum::http::HeaderValue::from_str(&size.to_string())
                    .map_err(|_| ApiErr(LatticeError::internal("bad size")))?,
            );
            Ok(resp)
        }
    }
}

/// Source package PUT/GET path (same path, different methods).
fn source_path(plugin_id: &str, version: &str) -> String {
    format!("/v1/hub/plugins/{plugin_id}/versions/{version}/source")
}

/// Source package object key: `{plugin_id}/{version}/source/{asset_name}` (⑥ §4.1).
fn source_object_key(plugin_id: &str, version: &str, asset_name: &str) -> String {
    format!("{plugin_id}/{version}/source/{asset_name}")
}

/// `source_upload` returned to the client in the POST response: only provided when "declared but not yet uploaded".
fn source_upload_of(plugin_id: &str, version: &pg::HubVersionRow) -> Value {
    match (&version.source_object_key, &version.source_sha256) {
        (None, Some(sha256)) => json!({
            "method": "PUT",
            "path": source_path(plugin_id, &version.version),
            "headers": {
                "Content-Type": "application/zip",
                "X-Content-SHA256": sha256,
            },
            "max_bytes": MAX_SOURCE_BYTES,
            "expires_at": chrono::Utc::now()
                + chrono::Duration::seconds(DRAFT_TTL_SECS as i64),
        }),
        _ => Value::Null,
    }
}

/// Response body for a successful source package upload (⑤ §12.4).
fn source_json(plugin_id: &str, row: &pg::HubVersionRow, idempotent: bool) -> Value {
    json!({
        "plugin_id": plugin_id,
        "version": row.version,
        "status": row.status,
        "source_asset_name": row.source_asset_name,
        "source_size": row.source_size,
        "source_sha256": row.source_sha256,
        "download_path": source_path(plugin_id, &row.version),
        "idempotent": idempotent,
    })
}

// ---------------------------------------------------------------------------
// §12.5 download / §12.6 delete
// ---------------------------------------------------------------------------

async fn download(
    State(st): State<Arc<AppState>>,
    user: AuthUser,
    Path((plugin_id, version)): Path<(String, String)>,
) -> ApiResult<Response> {
    let plugin = load_visible_plugin(&st, &user, &plugin_id).await?;
    let row = pg::hub_version(&st.db, &plugin.id, &version)
        .await?
        .ok_or_else(|| ApiErr(LatticeError::not_found("plugin version not found")))?;
    if row.status != "published" {
        return Err(ApiErr(LatticeError::not_found("plugin version not found")));
    }
    let bucket = st.s3.cfg().bucket_plugins.clone();
    let url = st.s3.presign_get(&bucket, &row.object_key, PRESIGN_TTL_SECS);

    // Count best-effort (⑤ §12.5): failures only alert, never affect the download
    let db = st.db.clone();
    let plugin_row_id = plugin.id.clone();
    let version_id = row.id.clone();
    tokio::spawn(async move {
        if let Err(e) = pg::hub_bump_plugin_download(&db, &plugin_row_id).await {
            tracing::warn!(error = %e, "hub plugin download counter failed");
        }
        if let Err(e) = pg::hub_bump_version_download(&db, &version_id).await {
            tracing::warn!(error = %e, "hub version download counter failed");
        }
    });

    let mut resp = StatusCode::FOUND.into_response();
    resp.headers_mut().insert(
        axum::http::header::LOCATION,
        axum::http::HeaderValue::from_str(&url)
            .map_err(|_| ApiErr(LatticeError::internal("bad presigned url")))?,
    );
    resp.headers_mut().insert(
        axum::http::HeaderName::from_static("x-content-sha256"),
        axum::http::HeaderValue::from_str(&row.sha256)
            .map_err(|_| ApiErr(LatticeError::internal("bad sha256")))?,
    );
    resp.headers_mut().insert(
        axum::http::HeaderName::from_static("x-content-length"),
        axum::http::HeaderValue::from_str(&row.size.to_string())
            .map_err(|_| ApiErr(LatticeError::internal("bad size")))?,
    );
    Ok(resp)
}

async fn delete_version(
    State(st): State<Arc<AppState>>,
    user: AuthUser,
    Path((plugin_id, version)): Path<(String, String)>,
) -> ApiResult<Response> {
    let plugin = load_visible_plugin(&st, &user, &plugin_id).await?;
    require_owner(&user, &plugin)?;
    if !pg::hub_remove_version(&st.db, &plugin.id, &version).await? {
        return Err(ApiErr(LatticeError::not_found("plugin version not found")));
    }
    audit(&st, &user, "hub.version.remove", &plugin_id, json!({ "version": version })).await;
    Ok(StatusCode::NO_CONTENT.into_response())
}

async fn delete_plugin(
    State(st): State<Arc<AppState>>,
    user: AuthUser,
    Path(plugin_id): Path<String>,
) -> ApiResult<Response> {
    let plugin = load_visible_plugin(&st, &user, &plugin_id).await?;
    require_owner(&user, &plugin)?;
    if !pg::hub_remove_plugin(&st.db, &plugin.id).await? {
        return Err(ApiErr(LatticeError::not_found("plugin not found")));
    }
    audit(&st, &user, "hub.plugin.remove", &plugin_id, json!({})).await;
    Ok(StatusCode::NO_CONTENT.into_response())
}

fn require_owner(user: &AuthUser, plugin: &pg::HubPluginRow) -> ApiResult<()> {
    if plugin.owner_id != user.user_id && !user.is_admin() {
        return Err(ApiErr(
            LatticeError::forbidden("only the owner can change this plugin").with_reason("not_owner"),
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// §12.7 install records and plugin data sync
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct InstallsQuery {
    #[serde(default)]
    include_data: Option<String>,
}

async fn list_installs(
    State(st): State<Arc<AppState>>,
    user: AuthUser,
    Query(q): Query<InstallsQuery>,
) -> ApiResult<Response> {
    let include_data = matches!(q.include_data.as_deref(), Some("1") | Some("true"));
    let rows = pg::hub_installs(&st.db, &user.user_id, include_data).await?;

    let mut items = Vec::with_capacity(rows.len());
    for row in rows {
        let plugin = pg::hub_plugin_by_plugin_id(&st.db, &row.plugin_id).await?;
        items.push(json!({
            "plugin_id": row.plugin_id,
            "version": row.version,
            "enabled": row.enabled,
            "data_rev": row.data_rev,
            "data_updated_at": row.data_updated_at,
            "last_device": row.last_device,
            "updated_at": row.updated_at,
            "plugin": plugin.map(|p| json!({
                "name": p.name, "icon": p.icon, "latest_version": p.latest_version,
                "status": p.status,
            })),
            "data": if include_data { Some(row.data) } else { None },
        }));
    }
    Ok(Json(json!({ "items": items })).into_response())
}

#[derive(Debug, Deserialize)]
struct InstallReq {
    version: Option<String>,
    enabled: Option<bool>,
    data: Option<Value>,
    data_rev: Option<i64>,
    device_id: Option<String>,
}

async fn upsert_install(
    State(st): State<Arc<AppState>>,
    user: AuthUser,
    Path(plugin_id): Path<String>,
    Query(q): Query<std::collections::HashMap<String, String>>,
    Json(req): Json<InstallReq>,
) -> ApiResult<Response> {
    rate_limit(&st, "sync", &user.user_id, 60, 120, "hub_sync").await?;
    if req.version.is_none() && req.enabled.is_none() && req.data.is_none() {
        return Err(ApiErr(
            LatticeError::format("nothing to sync: give version, enabled or data")
                .with_reason("empty_update"),
        ));
    }
    if let Some(v) = &req.version {
        if !is_semver(v) {
            return Err(ApiErr(
                LatticeError::format("invalid version").with_reason("version"),
            ));
        }
    }
    if let Some(d) = &req.data {
        let size = serde_json::to_vec(d).map(|b| b.len()).unwrap_or(usize::MAX);
        if size > MAX_DATA_BYTES {
            return Err(ApiErr(
                LatticeError::too_large(format!("plugin data {size} bytes exceeds {MAX_DATA_BYTES}"))
                    .with_reason("data")
                    .with_detail("max_bytes", json!(MAX_DATA_BYTES)),
            ));
        }
        if req.data_rev.is_none() {
            return Err(ApiErr(
                LatticeError::format("data_rev is required when submitting data")
                    .with_reason("data_rev"),
            ));
        }
    }
    let force = matches!(q.get("force").map(String::as_str), Some("1") | Some("true"));

    let outcome = pg::hub_install_upsert(
        &st.db,
        &user.user_id,
        &plugin_id,
        req.version.as_deref(),
        req.enabled,
        req.data.as_ref(),
        req.data_rev,
        req.device_id.as_deref(),
        force,
    )
    .await?;

    match outcome {
        HubInstallOutcome::Created(row) => Ok((
            StatusCode::CREATED,
            Json(install_json(&row, req.data.is_some())),
        )
            .into_response()),
        HubInstallOutcome::Updated(row) => {
            Ok(Json(install_json(&row, req.data.is_some())).into_response())
        }
        HubInstallOutcome::Conflict(row) => Err(ApiErr(
            LatticeError::conflict("plugin data was changed by another device")
                .with_reason("data_conflict")
                .with_detail(
                    "server",
                    json!({
                        "data_rev": row.data_rev,
                        "data_updated_at": row.data_updated_at,
                        "updated_at": row.updated_at,
                    }),
                ),
        )),
    }
}

async fn delete_install(
    State(st): State<Arc<AppState>>,
    user: AuthUser,
    Path(plugin_id): Path<String>,
) -> ApiResult<Response> {
    // Idempotent: returns 204 even when the record does not exist (repeated "clear cloud record" clicks must not error)
    pg::hub_install_delete(&st.db, &user.user_id, &plugin_id).await?;
    audit(&st, &user, "hub.install.remove", &plugin_id, json!({})).await;
    Ok(StatusCode::NO_CONTENT.into_response())
}

// ---------------------------------------------------------------------------
// §12.8 statistics
// ---------------------------------------------------------------------------

async fn stats(State(st): State<Arc<AppState>>, user: AuthUser) -> ApiResult<Response> {
    user.require_read()?;
    Ok(Json(pg::hub_stats(&st.db).await?).into_response())
}

// ---------------------------------------------------------------------------
// Validation (design §17.16)
// ---------------------------------------------------------------------------

fn validate_create(req: &CreateReq) -> ApiResult<()> {
    if !valid_plugin_id(&req.plugin_id) {
        return Err(ApiErr(
            LatticeError::format("invalid plugin_id").with_reason("plugin_id"),
        ));
    }
    if !is_semver(&req.version) {
        return Err(ApiErr(
            LatticeError::format("invalid version").with_reason("version"),
        ));
    }
    let name = req.name.trim();
    if name.is_empty() || name.chars().count() > MAX_NAME {
        return Err(ApiErr(
            LatticeError::format("name must be 1..=64 chars").with_reason("name"),
        ));
    }
    if req.description.chars().count() > MAX_DESCRIPTION {
        return Err(ApiErr(
            LatticeError::format("description too long").with_reason("description"),
        ));
    }
    if let Some(r) = &req.readme {
        if r.len() > MAX_README {
            return Err(ApiErr(
                LatticeError::format("readme too long").with_reason("readme"),
            ));
        }
    }
    if let Some(i) = &req.icon {
        if i.chars().count() > MAX_ICON {
            return Err(ApiErr(
                LatticeError::format("icon too long").with_reason("icon"),
            ));
        }
    }
    if req.changelog.chars().count() > MAX_CHANGELOG {
        return Err(ApiErr(
            LatticeError::format("changelog too long").with_reason("changelog"),
        ));
    }
    if req.tags.len() > MAX_TAGS || req.tags.iter().any(|t| t.chars().count() > MAX_TAG) {
        return Err(ApiErr(
            LatticeError::format("too many or too long tags").with_reason("tags"),
        ));
    }
    let manifest_bytes = serde_json::to_vec(&req.manifest).map(|b| b.len()).unwrap_or(usize::MAX);
    if manifest_bytes > MAX_MANIFEST {
        return Err(ApiErr(
            LatticeError::format("manifest too large").with_reason("manifest"),
        ));
    }
    let mid = req.manifest.get("id").and_then(Value::as_str).unwrap_or_default();
    let mver = req.manifest.get("version").and_then(Value::as_str).unwrap_or_default();
    if mid != req.plugin_id || mver != req.version {
        return Err(ApiErr(
            LatticeError::format("manifest.id/version must match the request")
                .with_reason("manifest_mismatch"),
        ));
    }
    if !valid_asset_name(&req.asset_name) {
        return Err(ApiErr(
            LatticeError::format("invalid asset_name").with_reason("asset_name"),
        ));
    }
    if req.size <= 0 || req.size as usize > MAX_PACKAGE_BYTES {
        return Err(ApiErr(
            LatticeError::too_large("size must be 1..=20MiB")
                .with_reason("size")
                .with_detail("max_bytes", json!(MAX_PACKAGE_BYTES)),
        ));
    }
    if !is_sha256_hex(&req.sha256) {
        return Err(ApiErr(
            LatticeError::format("sha256 must be 64 lowercase hex chars").with_reason("sha256"),
        ));
    }
    if let Some(s) = &req.source {
        validate_source_meta(s)?;
    }
    Ok(())
}

/// Source package declaration validation (v2 contract §1.2: once `source{}` is present, all three fields must be valid, otherwise 422).
///
/// The fourth column `source_object_key` is derived server-side from `{plugin_id}/{version}/source/{asset_name}`
/// and cannot be specified by the client (otherwise objects could be written under someone else's prefix).
fn validate_source_meta(s: &SourceMetaReq) -> ApiResult<()> {
    if !valid_asset_name(&s.asset_name) {
        return Err(ApiErr(
            LatticeError::format("invalid source asset_name").with_reason("source_asset_name"),
        ));
    }
    if s.size <= 0 || s.size as usize > MAX_SOURCE_BYTES {
        return Err(ApiErr(
            LatticeError::format(format!("source size must be 1..={MAX_SOURCE_BYTES}"))
                .with_reason("source_size")
                .with_detail("max_bytes", json!(MAX_SOURCE_BYTES)),
        ));
    }
    if !is_sha256_hex(&s.sha256) {
        return Err(ApiErr(
            LatticeError::format("source sha256 must be 64 lowercase hex chars")
                .with_reason("source_sha256"),
        ));
    }
    Ok(())
}

pub fn compare_semver(a: &str, b: &str) -> Ordering {
    let (a_core, a_pre) = split_semver(a);
    let (b_core, b_pre) = split_semver(b);
    for (x, y) in a_core.iter().zip(b_core.iter()) {
        match x.cmp(y) {
            Ordering::Equal => {}
            other => return other,
        }
    }
    match (a_pre, b_pre) {
        (None, None) => Ordering::Equal,
        (None, Some(_)) => Ordering::Greater, // 1.0.0 > 1.0.0-rc.1
        (Some(_), None) => Ordering::Less,
        (Some(x), Some(y)) => {
            let xs: Vec<&str> = x.split('.').collect();
            let ys: Vec<&str> = y.split('.').collect();
            for (p, q) in xs.iter().zip(ys.iter()) {
                let ord = match (p.parse::<u64>(), q.parse::<u64>()) {
                    (Ok(pi), Ok(qi)) => pi.cmp(&qi),
                    (Ok(_), Err(_)) => Ordering::Less,
                    (Err(_), Ok(_)) => Ordering::Greater,
                    (Err(_), Err(_)) => p.cmp(q),
                };
                if ord != Ordering::Equal {
                    return ord;
                }
            }
            xs.len().cmp(&ys.len())
        }
    }
}

fn split_semver(v: &str) -> (Vec<u64>, Option<&str>) {
    let v = v.split('+').next().unwrap_or(v);
    let (core, pre) = match v.split_once('-') {
        Some((c, p)) => (c, Some(p)),
        None => (v, None),
    };
    let nums = core
        .split('.')
        .map(|s| s.parse::<u64>().unwrap_or(0))
        .collect::<Vec<_>>();
    (nums, pre)
}

pub fn is_semver(v: &str) -> bool {
    let v = v.split('+').next().unwrap_or(v);
    let (core, pre) = match v.split_once('-') {
        Some((c, p)) => (c, Some(p)),
        None => (v, None),
    };
    let parts: Vec<&str> = core.split('.').collect();
    if parts.len() != 3 || parts.iter().any(|p| p.is_empty() || !p.chars().all(|c| c.is_ascii_digit())) {
        return false;
    }
    if let Some(p) = pre {
        if p.is_empty()
            || p.len() > 32
            || !p
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
        {
            return false;
        }
    }
    true
}

pub fn valid_plugin_id(id: &str) -> bool {
    let bytes = id.as_bytes();
    if bytes.len() < 2 || bytes.len() > 64 {
        return false;
    }
    if !(bytes[0].is_ascii_lowercase() || bytes[0].is_ascii_digit()) {
        return false;
    }
    bytes
        .iter()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'.' || *b == b'_' || *b == b'-')
}

fn valid_asset_name(name: &str) -> bool {
    if name.len() < 5 || name.len() > 128 {
        return false;
    }
    if !name.ends_with(".zip") {
        return false;
    }
    name.bytes().next().map(|b| b.is_ascii_alphanumeric()).unwrap_or(false)
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-')
}

fn is_sha256_hex(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

// ---------------------------------------------------------------------------
// Package structure validation (no extraction, no execution)
// ---------------------------------------------------------------------------

/// Basic usability of the zip central directory: `PK\x03\x04` header + locatable EOCD + central directory start in bounds.
/// Returns `(entry count, central directory start)`. Shared by packages and source packages.
fn zip_central_dir(bytes: &[u8]) -> std::result::Result<(usize, usize), &'static str> {
    if bytes.len() < 22 || &bytes[..4] != b"PK\x03\x04" {
        return Err("not a zip archive");
    }
    let eocd = find_eocd(bytes).ok_or("zip end-of-central-directory not found")?;
    if eocd + 22 > bytes.len() {
        return Err("zip end-of-central-directory out of range");
    }
    let count = u16::from_le_bytes([bytes[eocd + 10], bytes[eocd + 11]]) as usize;
    let cd_offset = u32::from_le_bytes([
        bytes[eocd + 16],
        bytes[eocd + 17],
        bytes[eocd + 18],
        bytes[eocd + 19],
    ]) as usize;
    if count == 0 || cd_offset + 46 > bytes.len() {
        return Err("zip is empty or has no central directory");
    }
    Ok((count, cd_offset))
}

/// Read the entry name at offset `off` in the central directory, and return the next entry offset.
fn zip_entry_at(bytes: &[u8], off: usize) -> std::result::Result<(&[u8], usize), &'static str> {
    if off + 46 > bytes.len() || &bytes[off..off + 4] != b"PK\x01\x02" {
        return Err("corrupt zip central directory");
    }
    let name_len = u16::from_le_bytes([bytes[off + 28], bytes[off + 29]]) as usize;
    let extra_len = u16::from_le_bytes([bytes[off + 30], bytes[off + 31]]) as usize;
    let comment_len = u16::from_le_bytes([bytes[off + 32], bytes[off + 33]]) as usize;
    let name_start = off + 46;
    let name_end = name_start + name_len;
    if name_end > bytes.len() {
        return Err("corrupt zip entry name");
    }
    Ok((&bytes[name_start..name_end], name_end + extra_len + comment_len))
}

/// Zip central directory validation: valid zip, contains `plugin.json`, entry names must not be absolute paths or contain `..`.
fn validate_package(bytes: &[u8]) -> std::result::Result<(), &'static str> {
    let (count, cd_offset) = zip_central_dir(bytes)?;

    let mut off = cd_offset;
    let mut saw_manifest = false;
    for _ in 0..count {
        let (raw_name, next) = zip_entry_at(bytes, off)?;
        let name = String::from_utf8_lossy(raw_name).replace('\\', "/");
        if is_unsafe_entry_name(&name) {
            return Err("zip entry uses an unsafe path");
        }
        if name == "plugin.json" || name.ends_with("/plugin.json") {
            saw_manifest = true;
        }
        off = next;
    }
    if !saw_manifest {
        return Err("zip does not contain plugin.json");
    }
    Ok(())
}

fn is_unsafe_entry_name(name: &str) -> bool {
    if name.starts_with('/') || name.starts_with('\\') {
        return true;
    }
    let bytes = name.as_bytes();
    if bytes.len() > 1 && bytes[1] == b':' {
        return true; // C:\ etc.
    }
    name.split('/').any(|seg| seg == "..")
}

fn find_eocd(bytes: &[u8]) -> Option<usize> {
    let start = bytes.len().saturating_sub(22 + 65_535);
    (start..=bytes.len().saturating_sub(22))
        .rev()
        .find(|&i| &bytes[i..i + 4] == b"PK\x05\x06")
}

// ---------------------------------------------------------------------------
// Source package structure validation (v2 contract §1.3 / §1.4)
//
// Difference from packages: a source package may be a project directory and is **not required** to contain plugin.json; but if it does,
// its `id` must equal the requested plugin_id. The server still does not extract the whole package or execute code;
// it locates plugin.json via the central directory and extracts **that single entry** (≤1MiB, zip-bomb protection).
// ---------------------------------------------------------------------------

/// One entry in the source zip central directory (only the fields needed to locate plugin.json).
struct SourceZipEntry {
    method: u16,
    compressed_size: usize,
    uncompressed_size: usize,
    local_offset: usize,
    /// Entry name depth: `plugin.json` = 0, `<dir>/plugin.json` = 1
    depth: usize,
}

/// Validate a source package (v2 contract §1.3):
/// - PK header + readable central directory; entry names must not be absolute paths / contain `..`;
/// - plugin.json is not required;
/// - if present (root directory first, then a unique top-level directory), its `id` must equal plugin_id.
fn validate_source_package(bytes: &[u8], plugin_id: &str) -> std::result::Result<(), &'static str> {
    let (count, cd_offset) = zip_central_dir(bytes)?;

    let mut off = cd_offset;
    let mut manifest: Option<SourceZipEntry> = None;
    for _ in 0..count {
        let (raw_name, next) = zip_entry_at(bytes, off)?;
        let name = String::from_utf8_lossy(raw_name).replace('\\', "/");
        if is_unsafe_entry_name(&name) {
            return Err("zip entry uses an unsafe path");
        }
        if !name.ends_with('/') {
            let depth = name.matches('/').count();
            let is_manifest = (depth == 0 && name == "plugin.json")
                || (depth == 1 && name.ends_with("/plugin.json"));
            if is_manifest && manifest.as_ref().map(|m| depth < m.depth).unwrap_or(true) {
                manifest = Some(SourceZipEntry {
                    method: u16::from_le_bytes([bytes[off + 10], bytes[off + 11]]),
                    compressed_size: u32::from_le_bytes([
                        bytes[off + 20],
                        bytes[off + 21],
                        bytes[off + 22],
                        bytes[off + 23],
                    ]) as usize,
                    uncompressed_size: u32::from_le_bytes([
                        bytes[off + 24],
                        bytes[off + 25],
                        bytes[off + 26],
                        bytes[off + 27],
                    ]) as usize,
                    local_offset: u32::from_le_bytes([
                        bytes[off + 42],
                        bytes[off + 43],
                        bytes[off + 44],
                        bytes[off + 45],
                    ]) as usize,
                    depth,
                });
            }
        }
        off = next;
    }

    let Some(entry) = manifest else {
        // A source package without plugin.json: valid (a project directory is fine), no id check
        return Ok(());
    };
    let manifest_bytes = read_source_manifest_entry(bytes, &entry)?;
    let parsed: Value = serde_json::from_slice(&manifest_bytes)
        .map_err(|_| "zip plugin.json is not valid JSON")?;
    let id = parsed
        .get("id")
        .and_then(Value::as_str)
        .ok_or("zip plugin.json has no string id")?;
    if id != plugin_id {
        return Err("zip plugin.json id does not match the plugin id");
    }
    Ok(())
}

/// Read `plugin.json` per the central directory location (stored: take directly; deflate: decompress).
fn read_source_manifest_entry(
    bytes: &[u8],
    entry: &SourceZipEntry,
) -> std::result::Result<Vec<u8>, &'static str> {
    if entry.uncompressed_size > MAX_SOURCE_MANIFEST_BYTES {
        return Err("zip plugin.json is too large");
    }
    // The local file header's extra length may differ from the central directory; the data start must use the local header
    if entry.local_offset + 30 > bytes.len() || &bytes[entry.local_offset..entry.local_offset + 4] != b"PK\x03\x04" {
        return Err("corrupt zip local header");
    }
    let local = entry.local_offset;
    let name_len = u16::from_le_bytes([bytes[local + 26], bytes[local + 27]]) as usize;
    let extra_len = u16::from_le_bytes([bytes[local + 28], bytes[local + 29]]) as usize;
    let data_start = local
        .checked_add(30 + name_len + extra_len)
        .ok_or("corrupt zip local header")?;
    let data_end = data_start
        .checked_add(entry.compressed_size)
        .ok_or("corrupt zip entry size")?;
    if data_end > bytes.len() {
        return Err("corrupt zip entry data");
    }
    let raw = &bytes[data_start..data_end];
    match entry.method {
        0 => Ok(raw.to_vec()),
        8 => inflate_raw(raw, entry.uncompressed_size),
        _ => Err("unsupported zip compression method for plugin.json"),
    }
}

// ---------------------------------------------------------------------------
// Minimal DEFLATE decompression (RFC 1951; only serves "read plugin.json from a source zip")
//
// The platform has no zip/flate dependency (adding one would change Cargo.toml/Cargo.lock, beyond this task's scope),
// while a source zip's plugin.json is usually Deflate-compressed, so this implements a read-only
// inflate: stored / fixed Huffman / dynamic Huffman blocks, output capped at 1MiB.
// ---------------------------------------------------------------------------

const MAX_DEFLATE_BITS: usize = 15;

/// LSB-first bit reader (DEFLATE bit order).
struct BitReader<'a> {
    data: &'a [u8],
    pos: usize,
    bit: u32,
}

impl<'a> BitReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        BitReader { data, pos: 0, bit: 0 }
    }

    fn bits(&mut self, n: u32) -> std::result::Result<u32, &'static str> {
        let mut v = 0u32;
        for i in 0..n {
            let byte = *self.data.get(self.pos).ok_or("truncated deflate stream")?;
            v |= (((byte >> self.bit) & 1) as u32) << i;
            self.bit += 1;
            if self.bit == 8 {
                self.bit = 0;
                self.pos += 1;
            }
        }
        Ok(v)
    }

    /// Skip the remaining bits of the current byte (stored blocks require byte alignment).
    fn align_byte(&mut self) {
        if self.bit != 0 {
            self.bit = 0;
            self.pos += 1;
        }
    }
}

/// Canonical Huffman decoding tables (same as puff.c: `counts` + `symbols` sorted by length).
struct Huffman {
    counts: [u16; MAX_DEFLATE_BITS + 1],
    symbols: Vec<u16>,
}

impl Huffman {
    fn build(lengths: &[u8]) -> std::result::Result<Self, &'static str> {
        let mut counts = [0u16; MAX_DEFLATE_BITS + 1];
        for &len in lengths {
            if len as usize > MAX_DEFLATE_BITS {
                return Err("invalid deflate code length");
            }
            counts[len as usize] += 1;
        }
        counts[0] = 0;
        // An over-subscribed code table cannot be produced by a valid encoder
        let mut left: i32 = 1;
        for len in 1..=MAX_DEFLATE_BITS {
            left <<= 1;
            left -= counts[len] as i32;
            if left < 0 {
                return Err("over-subscribed deflate huffman code");
            }
        }
        let mut offsets = [0u16; MAX_DEFLATE_BITS + 2];
        for len in 1..=MAX_DEFLATE_BITS {
            offsets[len + 1] = offsets[len] + counts[len];
        }
        let mut symbols = vec![0u16; lengths.len()];
        for (sym, &len) in lengths.iter().enumerate() {
            if len != 0 {
                let slot = offsets[len as usize] as usize;
                if slot >= symbols.len() {
                    return Err("invalid deflate huffman code");
                }
                symbols[slot] = sym as u16;
                offsets[len as usize] += 1;
            }
        }
        Ok(Huffman { counts, symbols })
    }

    fn decode(&self, r: &mut BitReader<'_>) -> std::result::Result<u16, &'static str> {
        let mut code: i32 = 0;
        let mut first: i32 = 0;
        let mut index: i32 = 0;
        for len in 1..=MAX_DEFLATE_BITS {
            code |= r.bits(1)? as i32;
            let count = self.counts[len] as i32;
            if code - first < count {
                let slot = (index + (code - first)) as usize;
                return self
                    .symbols
                    .get(slot)
                    .copied()
                    .ok_or("invalid deflate huffman code");
            }
            index += count;
            first += count;
            first <<= 1;
            code <<= 1;
        }
        Err("invalid deflate huffman code")
    }
}

const LEN_BASE: [u16; 29] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115,
    131, 163, 195, 227, 258,
];
const LEN_EXTRA: [u8; 29] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
];
const DIST_BASE: [u16; 30] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
    2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
];
const DIST_EXTRA: [u8; 30] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13,
];
const CODE_LENGTH_ORDER: [usize; 19] = [
    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
];

fn fixed_huffman() -> (Huffman, Huffman) {
    let mut lit_lengths = vec![0u8; 288];
    for (i, l) in lit_lengths.iter_mut().enumerate() {
        *l = match i {
            0..=143 => 8,
            144..=255 => 9,
            256..=279 => 7,
            _ => 8,
        };
    }
    let dist_lengths = vec![5u8; 30];
    (
        Huffman::build(&lit_lengths).expect("fixed literal table"),
        Huffman::build(&dist_lengths).expect("fixed distance table"),
    )
}

fn dynamic_huffman(
    r: &mut BitReader<'_>,
) -> std::result::Result<(Huffman, Huffman), &'static str> {
    let hlit = r.bits(5)? as usize + 257;
    let hdist = r.bits(5)? as usize + 1;
    let hclen = r.bits(4)? as usize + 4;
    if hlit > 286 || hdist > 32 {
        return Err("invalid deflate dynamic block sizes");
    }
    let mut cl_lengths = vec![0u8; 19];
    for &idx in CODE_LENGTH_ORDER.iter().take(hclen) {
        cl_lengths[idx] = r.bits(3)? as u8;
    }
    let cl = Huffman::build(&cl_lengths)?;

    let mut lengths = vec![0u8; hlit + hdist];
    let mut i = 0usize;
    while i < lengths.len() {
        let sym = cl.decode(r)?;
        match sym {
            0..=15 => {
                lengths[i] = sym as u8;
                i += 1;
            }
            16 => {
                if i == 0 {
                    return Err("deflate repeat with no previous length");
                }
                let prev = lengths[i - 1];
                let repeat = 3 + r.bits(2)? as usize;
                if i + repeat > lengths.len() {
                    return Err("deflate code-length overrun");
                }
                for _ in 0..repeat {
                    lengths[i] = prev;
                    i += 1;
                }
            }
            17 => {
                let repeat = 3 + r.bits(3)? as usize;
                if i + repeat > lengths.len() {
                    return Err("deflate code-length overrun");
                }
                i += repeat;
            }
            18 => {
                let repeat = 11 + r.bits(7)? as usize;
                if i + repeat > lengths.len() {
                    return Err("deflate code-length overrun");
                }
                i += repeat;
            }
            _ => return Err("invalid deflate code-length symbol"),
        }
    }
    if lengths[256] == 0 {
        return Err("deflate has no end-of-block code");
    }
    let lit = Huffman::build(&lengths[..hlit])?;
    let dist = Huffman::build(&lengths[hlit..])?;
    Ok((lit, dist))
}

fn inflate_block(
    r: &mut BitReader<'_>,
    lit: &Huffman,
    dist: &Huffman,
    out: &mut Vec<u8>,
    cap: usize,
) -> std::result::Result<(), &'static str> {
    loop {
        let sym = lit.decode(r)?;
        if sym < 256 {
            out.push(sym as u8);
            if out.len() > cap {
                return Err("zip plugin.json is too large");
            }
        } else if sym == 256 {
            return Ok(());
        } else {
            let idx = sym as usize - 257;
            if idx >= LEN_BASE.len() {
                return Err("invalid deflate length symbol");
            }
            let len = LEN_BASE[idx] as usize + r.bits(LEN_EXTRA[idx] as u32)? as usize;
            let dsym = dist.decode(r)? as usize;
            if dsym >= DIST_BASE.len() {
                return Err("invalid deflate distance symbol");
            }
            let distance = DIST_BASE[dsym] as usize + r.bits(DIST_EXTRA[dsym] as u32)? as usize;
            if distance > out.len() {
                return Err("deflate distance out of range");
            }
            if out.len() + len > cap {
                return Err("zip plugin.json is too large");
            }
            for _ in 0..len {
                let b = out[out.len() - distance];
                out.push(b);
            }
        }
    }
}

/// Decompress a raw DEFLATE stream (no zlib/gzip wrapper; output cap = `MAX_SOURCE_MANIFEST_BYTES`).
fn inflate_raw(
    input: &[u8],
    expected_size: usize,
) -> std::result::Result<Vec<u8>, &'static str> {
    if expected_size > MAX_SOURCE_MANIFEST_BYTES {
        return Err("zip plugin.json is too large");
    }
    let cap = MAX_SOURCE_MANIFEST_BYTES;
    let mut r = BitReader::new(input);
    let mut out: Vec<u8> = Vec::with_capacity(expected_size.min(4096));
    loop {
        let last = r.bits(1)?;
        let btype = r.bits(2)?;
        match btype {
            0 => {
                r.align_byte();
                let len = r.bits(16)? as usize;
                let nlen = r.bits(16)? as usize;
                if len != (!nlen) & 0xFFFF {
                    return Err("corrupt deflate stored block");
                }
                if out.len() + len > cap {
                    return Err("zip plugin.json is too large");
                }
                for _ in 0..len {
                    out.push(r.bits(8)? as u8);
                }
            }
            1 => {
                let (lit, dist) = fixed_huffman();
                inflate_block(&mut r, &lit, &dist, &mut out, cap)?;
            }
            2 => {
                let (lit, dist) = dynamic_huffman(&mut r)?;
                inflate_block(&mut r, &lit, &dist, &mut out, cap)?;
            }
            _ => return Err("invalid deflate block type"),
        }
        if last == 1 {
            return Ok(out);
        }
    }
}

// ---------------------------------------------------------------------------
// General helpers
// ---------------------------------------------------------------------------

async fn rate_limit(
    st: &Arc<AppState>,
    scope: &str,
    user: &str,
    window_secs: u64,
    limit: i64,
    reason: &str,
) -> ApiResult<()> {
    let key = lattice_core::keys::ratelimit_hub(scope, user);
    let hits = st.redis.bump_rate(&key, window_secs).await.unwrap_or(0);
    if hits > limit {
        return Err(ApiErr(
            LatticeError::rate(format!("hub {scope} rate limit exceeded")).with_reason(reason),
        ));
    }
    Ok(())
}

/// Hub audit helper: the client plugin center is not a mandatory admin audit point (failures do not roll back operations or surface to callers),
/// but it still goes through the unified audit write entry `routing::audit::audit_emit`:
/// - NATS bus mode → `audit.log` audit stream (durable consumer persists to PG, replayable);
/// - Redis bus/publish failure → audit_emit synchronously degrades to a direct PG write.
/// Write failures only WARN (preserving the existing "audit is best-effort and never blocks plugin operations" semantics).
async fn audit(st: &Arc<AppState>, user: &AuthUser, action: &str, target: &str, detail: Value) {
    if let Err(e) = crate::routing::audit::audit_emit(
        st,
        Some(&user.user_id),
        action,
        Some(target),
        &detail,
        None,
    )
    .await
    {
        tracing::warn!(error = %e, action, "hub audit write failed");
    }
}

fn header_str<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

fn hex_lower(raw: &[u8]) -> String {
    raw.iter().map(|b| format!("{b:02x}")).collect()
}

fn download_path(plugin_id: &str, version: &str) -> String {
    format!("/v1/hub/plugins/{plugin_id}/versions/{version}/download")
}

fn plugin_json(p: &pg::HubPluginRow) -> Value {
    json!({
        "plugin_id": p.plugin_id,
        "name": p.name,
        "description": p.description,
        "readme": p.readme,
        "icon": p.icon,
        "category": p.category,
        "tags": p.tags,
        "owner": {
            "id": p.owner_id,
            "username": p.owner_username,
            "display_name": p.owner_display_name,
        },
        "status": p.status,
        "latest_version": p.latest_version,
        "downloads": p.downloads,
        "created_at": p.created_at,
        "updated_at": p.updated_at,
    })
}

fn version_json(v: &pg::HubVersionRow) -> Value {
    json!({
        "version": v.version,
        "asset_name": v.asset_name,
        "size": v.size,
        "sha256": v.sha256,
        "status": v.status,
        "downloads": v.downloads,
        "published_at": v.published_at,
        "has_source": v.source_object_key.is_some(),
        "source_asset_name": v.source_asset_name,
        "source_size": v.source_size,
        "source_sha256": v.source_sha256,
    })
}

fn install_json(row: &pg::HubInstallRow, include_data: bool) -> Value {
    json!({
        "plugin_id": row.plugin_id,
        "version": row.version,
        "enabled": row.enabled,
        "data_rev": row.data_rev,
        "data_updated_at": row.data_updated_at,
        "last_device": row.last_device,
        "updated_at": row.updated_at,
        "data": if include_data { Some(row.data.clone()) } else { None },
    })
}

// `install_json`'s include_data parameter is reserved for a future "PUT echo data" use; currently only the record layer uses it.
#[allow(dead_code)]
fn _keep_install_json_signature() {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn semver_ordering() {
        assert_eq!(compare_semver("1.4.2", "1.4.1"), Ordering::Greater);
        assert_eq!(compare_semver("1.10.0", "1.9.9"), Ordering::Greater);
        assert_eq!(compare_semver("1.0.0", "1.0.0-rc.1"), Ordering::Greater);
        assert_eq!(compare_semver("1.0.0-rc.2", "1.0.0-rc.1"), Ordering::Greater);
        assert_eq!(compare_semver("1.0.0", "1.0.0"), Ordering::Equal);
        assert!(is_semver("0.2.0"));
        assert!(is_semver("1.4.2-beta.1"));
        assert!(!is_semver("1.4"));
        assert!(!is_semver("v1.4.2"));
        assert!(!is_semver("1.4.2.1"));
    }

    #[test]
    fn plugin_id_rules_match_doc() {
        assert!(valid_plugin_id("task-planner"));
        assert!(valid_plugin_id("plugin.demo_2"));
        assert!(!valid_plugin_id("Task-Planner"));
        assert!(!valid_plugin_id("a"));
        assert!(!valid_plugin_id("-x"));
        assert!(!valid_plugin_id("a/b"));
    }

    #[test]
    fn package_validation_rejects_traversal_and_missing_manifest() {
        // Minimal parseable zip: one central directory entry (field offsets strictly per ZIP APPNOTE)
        fn zip_with(name: &str) -> Vec<u8> {
            let mut central = Vec::new();
            central.extend_from_slice(b"PK\x01\x02");
            central.extend_from_slice(&[0u8; 24]); // 4..27: version/flags/compression/time/CRC/size
            central.extend_from_slice(&(name.len() as u16).to_le_bytes()); // 28..29: name length
            central.extend_from_slice(&[0u8; 16]); // 30..45: extra/comment/disk/attrs/offset
            central.extend_from_slice(name.as_bytes()); // 46..: name
            let cd_offset = 4u32;
            let mut out = b"PK\x03\x04".to_vec();
            out.extend_from_slice(&central);
            let eocd_pos = out.len();
            out.extend_from_slice(b"PK\x05\x06");
            out.extend_from_slice(&[0u8; 4]); // 4..7: disk
            out.extend_from_slice(&1u16.to_le_bytes()); // 8..9: entries on this disk
            out.extend_from_slice(&1u16.to_le_bytes()); // 10..11: total entries
            out.extend_from_slice(&(central.len() as u32).to_le_bytes()); // 12..15
            out.extend_from_slice(&cd_offset.to_le_bytes()); // 16..19
            out.extend_from_slice(&[0u8; 2]); // 20..21: comment len
            assert_eq!(find_eocd(&out), Some(eocd_pos));
            out
        }
        assert!(validate_package(&zip_with("plugin.json")).is_ok());
        assert!(validate_package(&zip_with("task-planner/plugin.json")).is_ok());
        assert!(validate_package(&zip_with("main.cjs")).is_err());
        assert!(validate_package(&zip_with("../plugin.json")).is_err());
        assert!(validate_package(&zip_with("/plugin.json")).is_err());
        assert!(validate_package(b"not a zip").is_err());
    }

    #[test]
    fn sha_and_asset_rules() {
        assert!(is_sha256_hex(&"a".repeat(64)));
        assert!(!is_sha256_hex(&"A".repeat(64)));
        assert!(!is_sha256_hex("abc"));
        assert!(valid_asset_name("task-planner-1.4.2.zip"));
        assert!(!valid_asset_name("a/b.zip"));
        assert!(!valid_asset_name("x.tar.gz"));
    }

    // -----------------------------------------------------------------------
    // v2 contract §1: version source package (structure validation / idempotency / 404 decisions)
    // -----------------------------------------------------------------------

    fn hex_bytes(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
            .collect()
    }

    /// Build a minimal zip parseable via the central directory (stored, entry content as-is).
    fn source_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut body: Vec<u8> = Vec::new();
        let mut central: Vec<u8> = Vec::new();
        for (name, data) in entries {
            let offset = body.len() as u32;
            // local file header (30 bytes)
            body.extend_from_slice(b"PK\x03\x04");
            body.extend_from_slice(&20u16.to_le_bytes()); // version needed
            body.extend_from_slice(&0u16.to_le_bytes()); // flags
            body.extend_from_slice(&0u16.to_le_bytes()); // method: stored
            body.extend_from_slice(&[0u8; 4]); // time + date
            body.extend_from_slice(&0u32.to_le_bytes()); // crc (validation does not read it)
            body.extend_from_slice(&(data.len() as u32).to_le_bytes()); // compressed size
            body.extend_from_slice(&(data.len() as u32).to_le_bytes()); // uncompressed size
            body.extend_from_slice(&(name.len() as u16).to_le_bytes());
            body.extend_from_slice(&0u16.to_le_bytes()); // extra len
            body.extend_from_slice(name.as_bytes());
            body.extend_from_slice(data);
            // central directory header (46 bytes)
            central.extend_from_slice(b"PK\x01\x02");
            central.extend_from_slice(&20u16.to_le_bytes()); // version made by
            central.extend_from_slice(&20u16.to_le_bytes()); // version needed
            central.extend_from_slice(&0u16.to_le_bytes()); // flags
            central.extend_from_slice(&0u16.to_le_bytes()); // method: stored
            central.extend_from_slice(&[0u8; 4]); // time + date
            central.extend_from_slice(&0u32.to_le_bytes()); // crc
            central.extend_from_slice(&(data.len() as u32).to_le_bytes());
            central.extend_from_slice(&(data.len() as u32).to_le_bytes());
            central.extend_from_slice(&(name.len() as u16).to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes()); // extra len
            central.extend_from_slice(&0u16.to_le_bytes()); // comment len
            central.extend_from_slice(&0u16.to_le_bytes()); // disk start
            central.extend_from_slice(&0u16.to_le_bytes()); // internal attr
            central.extend_from_slice(&0u32.to_le_bytes()); // external attr
            central.extend_from_slice(&offset.to_le_bytes());
            central.extend_from_slice(name.as_bytes());
        }
        let cd_offset = body.len() as u32;
        body.extend_from_slice(&central);
        body.extend_from_slice(b"PK\x05\x06");
        body.extend_from_slice(&[0u8; 4]); // disk / cd disk
        body.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        body.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        body.extend_from_slice(&(central.len() as u32).to_le_bytes());
        body.extend_from_slice(&cd_offset.to_le_bytes());
        body.extend_from_slice(&[0u8; 2]); // comment len
        body
    }

    /// Build a zip with "plugin.json compressed via deflate" (caller supplies the already-compressed bytes).
    fn source_zip_deflated(name: &str, manifest: &[u8], deflate: &[u8]) -> Vec<u8> {
        let mut body: Vec<u8> = Vec::new();
        let mut central: Vec<u8> = Vec::new();
        let offset = 0u32;
        body.extend_from_slice(b"PK\x03\x04");
        body.extend_from_slice(&20u16.to_le_bytes());
        body.extend_from_slice(&0u16.to_le_bytes());
        body.extend_from_slice(&8u16.to_le_bytes()); // method: deflate
        body.extend_from_slice(&[0u8; 4]);
        body.extend_from_slice(&0u32.to_le_bytes());
        body.extend_from_slice(&(deflate.len() as u32).to_le_bytes());
        body.extend_from_slice(&(manifest.len() as u32).to_le_bytes());
        body.extend_from_slice(&(name.len() as u16).to_le_bytes());
        body.extend_from_slice(&0u16.to_le_bytes());
        body.extend_from_slice(name.as_bytes());
        body.extend_from_slice(deflate);

        central.extend_from_slice(b"PK\x01\x02");
        central.extend_from_slice(&20u16.to_le_bytes());
        central.extend_from_slice(&20u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&8u16.to_le_bytes());
        central.extend_from_slice(&[0u8; 4]);
        central.extend_from_slice(&0u32.to_le_bytes());
        central.extend_from_slice(&(deflate.len() as u32).to_le_bytes());
        central.extend_from_slice(&(manifest.len() as u32).to_le_bytes());
        central.extend_from_slice(&(name.len() as u16).to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u32.to_le_bytes());
        central.extend_from_slice(&offset.to_le_bytes());
        central.extend_from_slice(name.as_bytes());

        let cd_offset = body.len() as u32;
        body.extend_from_slice(&central);
        body.extend_from_slice(b"PK\x05\x06");
        body.extend_from_slice(&[0u8; 4]);
        body.extend_from_slice(&1u16.to_le_bytes());
        body.extend_from_slice(&1u16.to_le_bytes());
        body.extend_from_slice(&(central.len() as u32).to_le_bytes());
        body.extend_from_slice(&cd_offset.to_le_bytes());
        body.extend_from_slice(&[0u8; 2]);
        body
    }

    #[test]
    fn source_zip_structure_and_manifest_id() {
        // A source package may have no plugin.json (project directory)
        let plain = source_zip(&[
            ("main.cjs", b"exports.install = function () {}\n"),
            ("renderer.mjs", b"export default {}\n"),
        ]);
        assert!(validate_source_package(&plain, "task-planner").is_ok());

        // Root plugin.json: id must equal plugin_id
        let root = source_zip(&[
            ("plugin.json", br#"{"id":"task-planner","version":"1.4.2"}"#),
            ("main.cjs", b"x"),
        ]);
        assert!(validate_source_package(&root, "task-planner").is_ok());
        assert_eq!(
            validate_source_package(&root, "other-plugin"),
            Err("zip plugin.json id does not match the plugin id")
        );

        // plugin.json under a unique top-level directory is also accepted (common source package shape)
        let nested = source_zip(&[(
            "task-planner-src/plugin.json",
            br#"{"id":"task-planner"}"#,
        )]);
        assert!(validate_source_package(&nested, "task-planner").is_ok());

        // Invalid manifests / invalid JSON / path traversal are all rejected
        assert!(validate_source_package(
            &source_zip(&[("plugin.json", b"not json")]),
            "task-planner"
        )
        .is_err());
        assert!(validate_source_package(
            &source_zip(&[("plugin.json", br#"{"version":"1.0.0"}"#)]),
            "task-planner"
        )
        .is_err());
        assert!(validate_source_package(
            &source_zip(&[("../plugin.json", br#"{"id":"task-planner"}"#)]),
            "task-planner"
        )
        .is_err());

        // Non-zip / empty zip
        assert!(validate_source_package(b"not a zip", "task-planner").is_err());
        assert!(validate_source_package(&source_zip(&[]), "task-planner").is_err());

        // plugin.json two or more directories deep is not treated as the package manifest (a source package may be any project directory)
        assert!(validate_source_package(
            &source_zip(&[("src/nested/plugin.json", br#"{"id":"other-plugin"}"#)]),
            "task-planner"
        )
        .is_ok());
    }

    #[test]
    fn inflate_reads_deflated_plugin_json() {
        // The fixture was generated by .NET DeflateStream (raw deflate, fixed-huffman),
        // the same shape as plugin.json from Windows Explorer "Compress to zip" / Compress-Archive.
        const MANIFEST: &str = r#"{"id":"task-planner","name":"Task Planner","version":"1.4.2"}"#;
        const DEFLATE_HEX: &str = "ab56ca4c51b2522a492cced62dc849cccb4b2d52d251ca4bcc4d058a8600451502e0a265a945c599f9794009433d133d23a55a00";
        let deflate = hex_bytes(DEFLATE_HEX);
        assert_eq!(
            inflate_raw(&deflate, MANIFEST.len()).unwrap(),
            MANIFEST.as_bytes()
        );

        let zip = source_zip_deflated("plugin.json", MANIFEST.as_bytes(), &deflate);
        assert!(validate_source_package(&zip, "task-planner").is_ok());
        assert_eq!(
            validate_source_package(&zip, "other-plugin"),
            Err("zip plugin.json id does not match the plugin id")
        );

        // A truncated deflate stream must error, not panic/overrun
        assert!(inflate_raw(&deflate[..deflate.len() / 2], MANIFEST.len()).is_err());

        // stored block (RFC 1951 btype=0): BFINAL=1 + LEN/NLEN + raw bytes
        let stored = hex_bytes("010300fcff616263");
        assert_eq!(inflate_raw(&stored, 3).unwrap(), b"abc");

        // dynamic Huffman block (btype=2): the fixture is produced by .NET DeflateStream compressing a random readme
        const DYN_MANIFEST: &str = r#"{"id":"task-planner","version":"1.4.2","readme":"GlYo8DawrVb2LHLjJnkddgn6J6Y1WbbOIhK6wh8fZJN6i6zCdRTF0AVqF3wTdK1hyvFyMR8ZusGfWc4j9us31sjfaZrMWwD1NVagykI6u61lWfctrTJ0YNHqIhxGodoaM0C0NA=="}"#;
        const DYN_DEFLATE_HEX: &str = "0dc9db0a82300000d07fd973894b1916f4108a770d42147d9b6ede9bb979c9a27fcfd773bea021e002262cbae3abc78c510e0e60a15c3403db034aaa74da85534c9e7407ab4f07cdc02b8ff3936ffbadcb3a422a865c94c224cfef4eeda1b5d6cacc0d51833e3a7944a67c8b47535923e2c17a5bcc2d7868d92cac3229d4f63c0b058ab6c4190f92d580618cabad73d08c609f94c5c423574e437b74eab735900107b22e87b7eb15fcfe";
        let dyn_deflate = hex_bytes(DYN_DEFLATE_HEX);
        // Low 3 bits of the first byte: BFINAL=1, BTYPE=10 (dynamic Huffman), ensuring this branch is really exercised
        assert_eq!(dyn_deflate[0] & 0b111, 0b101);
        assert_eq!(
            inflate_raw(&dyn_deflate, DYN_MANIFEST.len()).unwrap(),
            DYN_MANIFEST.as_bytes()
        );
        let dyn_zip = source_zip_deflated("plugin.json", DYN_MANIFEST.as_bytes(), &dyn_deflate);
        assert!(validate_source_package(&dyn_zip, "task-planner").is_ok());
    }

    #[test]
    fn source_meta_validation() {
        let ok = SourceMetaReq {
            asset_name: "task-planner-1.4.2-src.zip".into(),
            size: 812_345,
            sha256: "a".repeat(64),
        };
        assert!(validate_source_meta(&ok).is_ok());

        let reason = |s: &SourceMetaReq| {
            validate_source_meta(s)
                .unwrap_err()
                .0
                .details
                .as_ref()
                .and_then(|d| d.get("reason"))
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string()
        };
        let mut bad = ok.clone();
        bad.asset_name = "task-planner-src.tar.gz".into();
        assert_eq!(reason(&bad), "source_asset_name");
        let mut bad = ok.clone();
        bad.asset_name = "../src.zip".into();
        assert_eq!(reason(&bad), "source_asset_name");
        let mut bad = ok.clone();
        bad.size = 0;
        assert_eq!(reason(&bad), "source_size");
        let mut bad = ok.clone();
        bad.size = MAX_SOURCE_BYTES as i64 + 1;
        assert_eq!(reason(&bad), "source_size");
        let mut bad = ok.clone();
        bad.sha256 = "A".repeat(64);
        assert_eq!(reason(&bad), "source_sha256");
    }

    #[test]
    fn source_put_decision_idempotency_and_conflict() {
        let a = "a".repeat(64);
        let b = "b".repeat(64);
        // Already uploaded with the same sha -> idempotent
        assert_eq!(
            decide_source_put(Some(&a), Some(&a), &a),
            SourcePutDecision::Idempotent
        );
        // Already uploaded with a different sha -> 409 source_published (even if it also differs from the POST declaration)
        assert_eq!(
            decide_source_put(Some(&a), Some(&a), &b),
            SourcePutDecision::Conflict { published_sha256: a.clone() }
        );
        // Not uploaded: declaration exists but header mismatches -> 422 checksum
        assert_eq!(
            decide_source_put(Some(&a), None, &b),
            SourcePutDecision::ChecksumMismatch
        );
        // Not uploaded and matching -> may write the object
        assert_eq!(
            decide_source_put(Some(&a), None, &a),
            SourcePutDecision::Proceed
        );
        // No source declared at POST -> 422 source_not_declared
        assert_eq!(
            decide_source_put(None, None, &a),
            SourcePutDecision::NotDeclared
        );
        // An uppercase header and a lowercase sha are equivalent (server storage is always lowercase)
        assert_eq!(
            decide_source_put(Some(&a), None, &a.to_ascii_uppercase()),
            SourcePutDecision::Proceed
        );
        assert_eq!(
            source_object_key("task-planner", "1.4.2", "task-planner-1.4.2-src.zip"),
            "task-planner/1.4.2/source/task-planner-1.4.2-src.zip"
        );
    }

    #[test]
    fn source_download_visibility_404_decisions() {
        assert_eq!(
            decide_source_download("published", true),
            SourceDownloadDecision::Downloadable
        );
        // No source -> 404 source_missing
        assert_eq!(
            decide_source_download("published", false),
            SourceDownloadDecision::MissingSource
        );
        // pending draft / removed version: always 404 (no draft leakage, no reviving removed versions)
        assert_eq!(
            decide_source_download("pending", true),
            SourceDownloadDecision::VersionNotFound
        );
        assert_eq!(
            decide_source_download("pending", false),
            SourceDownloadDecision::VersionNotFound
        );
        assert_eq!(
            decide_source_download("removed", true),
            SourceDownloadDecision::VersionNotFound
        );
    }
}
