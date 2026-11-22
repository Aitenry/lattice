//! Generate the gRPC sidecar stub (`proto/lattice.proto` → `lattice.internal.v1`).
//!
//! Used only by this crate: the client (`PluginSidecar.Process`) lives in `src/sidecar/grpc.rs`,
//! and the mock server in tests uses the same generated code. Output goes to OUT_DIR and is not committed.
//!
//! Why reuse `proto/lattice.proto` instead of splitting out `proto/plugin_sidecar.proto`:
//! - The contract's single source of truth is doc ⑤ §10, and the proto source is the repo-root `proto/lattice.proto` (registered in doc ② §3.3);
//!   splitting the file would mean maintaining one contract in two places, which is bound to drift;
//! - A second proto in the same `package` would be rejected as duplicate symbols (ProcessReq/ProcessResp, etc.) by tools that compile all
//!   protos at once (protoc/buf), while a different package would change the gRPC service full name
//!   (`/lattice.internal.v1.PluginSidecar/Process`), which is incompatible with the real sidecar contract;
//! - Generation happens in **this crate's** OUT_DIR and does not collide with the NodeInternal that `lattice-node` generates
//!   (each crate includes its own copy; symbols are not shared).
//!
//! `protoc` comes from the prebuilt binary in `protoc-bin-vendored`, so host machines, CI, and Docker need no protobuf
//! compiler installed (same approach as `crates/lattice-node/build.rs`).
fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=../../proto/lattice.proto");
    if std::env::var_os("PROTOC").is_none() {
        if let Ok(path) = protoc_bin_vendored::protoc_bin_path() {
            std::env::set_var("PROTOC", path);
        }
    }
    // server(true): for the mock `PluginSidecar` server in integration tests; client(true): for production calls.
    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(&["../../proto/lattice.proto"], &["../../proto"])?;
    Ok(())
}
