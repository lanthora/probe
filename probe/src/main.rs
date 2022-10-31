use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use clap::Parser;
use log::{info, warn, LevelFilter};
use tokio::signal;

mod golang;
mod openssl;

#[derive(Debug, Parser)]
pub struct Opt {
    #[clap(short, long)]
    pid: Option<i32>,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let mut opt = Opt::parse();

    env_logger::builder()
        .format_timestamp(None)
        .filter_level(LevelFilter::Info)
        .init();

    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/probe"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/probe"
    ))?;

    if let Err(e) = BpfLogger::init(&mut bpf) {
        warn!("failed to initialize eBPF logger: {}", e);
    }

    openssl::load_and_attach(&mut bpf, &mut opt).ok();
    golang::load_and_attach(&mut bpf, &mut opt).ok();

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
