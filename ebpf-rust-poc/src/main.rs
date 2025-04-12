use anyhow::Context;
use aya::programs::UProbe;
use aya_log::EbpfLogger;
use aya::maps::HashMap;
use clap::Parser;
use log::info;
use tokio::signal;
use std::env;
use ebpf_rust_poc_common::AllocInfo;
use std::fs;
mod bpf_metrics;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "eth0")]
    iface: String,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    println!("Starting application...");

    env_logger::init();
    bpf_metrics::registry::MetricsRegistry::initialize();

    // This will include your eBPF object file as raw bytes at compile-time and load it at``
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Ebpf::load_file` instead.
    let mut bpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/ebpf-rust-poc"
    )))?;

    EbpfLogger::init(&mut bpf)?;
    attach_probes(&mut bpf)?;

    let alloc_blocks: HashMap<_, u64, AllocInfo> = HashMap::try_from(
        bpf.map_mut("allocated_blocks").context("failed to map allocated_blocks")?,
    )?;
    println!("Maps loaded");

    let container_ids = get_container_ids().context("Failed to retrieve container IDs")?;
    println!("Container IDs: {:?}", container_ids);

    loop {
        println!("allocated_blocks contents with size {}: ", alloc_blocks.iter().count());
        let mut cgroup_count_map: std::collections::HashMap<u64, (usize, usize)> = std::collections::HashMap::new();

        for alloc_map_entry in alloc_blocks.iter() {
            if let Ok((_, alloc_info)) = alloc_map_entry {
                let entry = cgroup_count_map.entry(alloc_info.cgroup).or_insert((0, 0));
                entry.0 += 1; // Increment count
                entry.1 += alloc_info.size as usize; // Add to total size
            }
        }
        for (cgroup_id, count) in cgroup_count_map.iter() {
            println!("Cgroup ID: {}, Alloc Count: {}, Alloc Amount in Bytes: {}", cgroup_id, count.0, count.1);
        }
        println!("---------------------------------");
        tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
    }

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}

fn attach_probes(bpf: &mut aya::Ebpf) -> Result<(), anyhow::Error> {
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

    Ok(())
}

fn get_container_ids() -> Result<Vec<String>, anyhow::Error> {
    let mut container_ids = Vec::new();

    // since this application will be running privileged with access to /proc, we get get the container ids from /proc/<pid>/cgroup (file)
    // the cgroup file contains the cgroup hierarchy for the process, including the container id
    // we can parse the cgroup file to get the container id
    // for example, a cgroup can look like this:
    // ::/kubelet.slice/kubelet-kubepods.slice/kubelet-kubepods-besteffort.slice/kubelet-kubepods-besteffort-pod0f1c0a01_f9b0_41ae_9d7e_15104d4f03ba.slice/cri-containerd-ac943021d695b61c1f27c60f6a634564c4f4c2dcb60f9a950e4a0b040df59228.scope
    // so given that we already have the PID, we can read the cgroup file and parse it to get the container id
    // the container id is the last part of the cgroup path, so we can split the path by / and get the last part (while cutting off the .scope part)
    // we can also check if the cgroup path contains cri-containerd, which is a good indicator that this is a container
    

    Ok(container_ids)
}