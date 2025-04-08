use anyhow::Context;
use aya::programs::{TracePoint, UProbe, Xdp, XdpFlags};
use aya_log::EbpfLogger;
use clap::Parser;
use log::info;
use tokio::signal; // (1)
mod bpf_metrics;
use bpf_metrics::{collector, exporter};

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "eth0")]
    iface: String, // (2)
}

#[tokio::main] // (3)
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();

    println!("Starting application...");

    env_logger::init();
    bpf_metrics::init_metrics();
    collector::collect();
    exporter::export();

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Ebpf::load_file` instead.
    // (4)
    // (5)
    let mut bpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/ebpf-rust-poc"
    )))?;
    EbpfLogger::init(&mut bpf)?;
    // (6)
    // let program: &mut Xdp = bpf.program_mut("xdp_hello").unwrap().try_into()?;
    // program.load()?; // (7)
    //                  // (8)
    // program.attach(&opt.iface, XdpFlags::SKB_MODE)
    //     .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

    // let mkdir_program: &mut TracePoint = bpf.program_mut("trace_mkdir").unwrap().try_into()?;
    // mkdir_program.load()?;
    // mkdir_program.attach("syscalls", "sys_enter_mkdir")?;

    println!("Attaching uprobes and uretprobes...");

    // Attach uprobe to malloc
    let malloc_uprobe: &mut UProbe = bpf.program_mut("track_malloc").unwrap().try_into()?;
    malloc_uprobe.load()?;
    malloc_uprobe.attach("malloc", "libc", None, None)?;
    println!("malloc uprobe attached");

    // Attach uretprobe to malloc
    let malloc_uretprobe: &mut UProbe = bpf.program_mut("track_malloc_ret").unwrap().try_into()?;
    malloc_uretprobe.load()?;
    malloc_uretprobe.attach("malloc", "libc", None, None)?;
    println!("malloc uretprobe attached");

    // Attach uprobe to free
    let free_uprobe: &mut UProbe = bpf.program_mut("track_free").unwrap().try_into()?;
    free_uprobe.load()?;
    free_uprobe.attach("free", "libc", None, None)?;
    println!("free uprobe attached");

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
