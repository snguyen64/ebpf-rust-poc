use anyhow::Context;
use aya::programs::UProbe;
use aya_log::EbpfLogger;
use aya::maps::HashMap;
use clap::Parser;
use log::info;
use opentelemetry::global::meter_provider;
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
    let mut cache = bpf_metrics::enricher::PodCache::initialize().await;
    let meter_provider = bpf_metrics::exporter::init_metrics();
    let registry = bpf_metrics::registry::MetricsRegistry::initialize();

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
        bpf.take_map("allocated_blocks").context("failed to map allocated_blocks")?,
    )?;
    println!("Maps loaded");

    // Todo this map should be updated every now and then
    let mut pid_map: HashMap<_, u32, u32> = HashMap::try_from(
        bpf.take_map("pid_map").context("failed to map PID_MAP")?,
    )?;
    println!("PID map loaded");
    for pid in cache.get_pids() {
        pid_map.insert(pid, 1, 0).context("failed to insert pid into pid_map")?;
        // todo remove pid from pid_map if not found in cache - doesnt matter for now since we aren't updating cache
    }

    loop {
        let mut pid_count_size_map: std::collections::HashMap<u32, (u64, u64)> = std::collections::HashMap::new();

        for alloc_map_entry in alloc_blocks.iter() {
            if let Ok((_, alloc_info)) = alloc_map_entry {
                // println!("ALLOC_INFO: PID: {}, Size: {}, Timestamp: {}, Cgroup ID: {}", alloc_info.pid, alloc_info.size, alloc_info.timestamp, alloc_info.cgroup);
                let entry = pid_count_size_map.entry(alloc_info.tgid).or_insert((0, 0));
                entry.0 += 1; // Increment count -- total number allocations for this pid
                entry.1 = entry.1.saturating_add(alloc_info.size as u64); // Add to total size for this pid
                // println!(
                //     "ENTRY: PID: {}, Size: {}, Allocations: {}",
                //     alloc_info.tgid, alloc_info.size, entry.0
                // );
            }
        }

        // for (pid, (count, size)) in pid_count_size_map.iter() {
        //     println!("map print: PID: {}, Allocations: {}, Total Size: {}", pid, count, size);
        // }

        for (pid, (count, size)) in pid_count_size_map.iter() {
            if let Some(container_id) = cache.get_container_id_by_pid(*pid) {
                if let Some(pod_info) = cache.get_pod_info_by_container_id(&container_id) {
                    // println!(
                    //     "METRIC: Container ID: {}, Pod: {} in Namespace: {}, Allocations: {}, Total Size: {}",
                    //     container_id, pod_info.pod_name, pod_info.namespace, count, *size
                    // );
                    registry.update_alloc_info(
                        &container_id,
                        &pod_info.namespace,
                        &pod_info.pod_name,
                        *size,
                    );
                }
            } else {
                println!("No container ID found for PID: {}", pid);
            }
        }
        tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
    }
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

