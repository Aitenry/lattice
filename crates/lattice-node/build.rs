//! Generates internal gRPC stubs (`proto/lattice.proto` → `lattice.internal.v1`).
//!
//! `protoc` comes from `protoc-bin-vendored` (prebuilt binaries per platform), so host/CI/Docker
//! need no system protobuf compiler; output lands in OUT_DIR and is not committed.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=../../proto/lattice.proto");
    if std::env::var_os("PROTOC").is_none() {
        if let Ok(path) = protoc_bin_vendored::protoc_bin_path() {
            std::env::set_var("PROTOC", path);
        }
    }
    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(&["../../proto/lattice.proto"], &["../../proto"])?;
    Ok(())
}
