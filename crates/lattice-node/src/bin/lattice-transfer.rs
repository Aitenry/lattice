//! `lattice-transfer` entry point (design §6.10).
//!
//! A stateless download data plane. It reads the same configuration file/environment as the
//! node and serves `GET|HEAD /t/{token}` plus health/readiness/metrics. Deploy it with the same
//! image as the node (`command: ["/usr/local/bin/lattice-transfer", "--config", ...]`) and run
//! as many replicas as the download traffic needs.

use lattice_node::config;
use lattice_node::transfer;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let cfg_path = args
        .iter()
        .position(|a| a == "--config")
        .and_then(|i| args.get(i + 1))
        .map(std::path::PathBuf::from)
        .or_else(|| std::env::var("LATTICE_CONFIG").ok().map(std::path::PathBuf::from));

    // Node-only startup work (pipeline/inspectable KEK) is deliberately skipped: this process
    // shares the deployment TOML but must not depend on node-local secrets or message-path config.
    let cfg = config::Config::load_for_transfer(cfg_path.as_deref())?;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(transfer::run(cfg))
}
