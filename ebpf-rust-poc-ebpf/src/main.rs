#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{
        self, bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_get_smp_processor_id, bpf_ktime_get_ns, bpf_probe_read, bpf_probe_read_user, generated::{bpf_get_current_cgroup_id, bpf_get_retval}
    }, macros::{map, uprobe, uretprobe}, maps::HashMap, programs::{ProbeContext, RetProbeContext}, EbpfContext
};
use aya_log_ebpf::info;
use ebpf_rust_poc_common::AllocInfo;

// Step 1: Malloc map. Key is the timestamp+pid of the call.
#[map(name = "malloc_map")]
static mut MALLOC_MAP: HashMap<u64, AllocInfo> = HashMap::with_max_entries(1024, 0);
// malloc info map of address to alloc info. This represents allocated blocks. The key is the address returned from the malloc call.
#[map(name = "allocated_blocks")]
static mut ALLOCATED_BLOCKS_MAP: HashMap<u64, AllocInfo> = HashMap::with_max_entries(1024, 0);
// todo we need to track uretprobe for malloc to get the return value (address) so we can free it later

#[uprobe]
pub fn track_malloc(ctx: ProbeContext) -> u32 {
    match unsafe { try_track_malloc(ctx) } {
        Ok(_) => 0,
        Err(_) => 1,
    }
}

unsafe fn try_track_malloc(ctx: ProbeContext) -> Result<(), u32> {
    // info!(&ctx, "malloc called");
    let pid = (bpf_get_current_pid_tgid() & 0xFFFFFFFF) as u32; // gets pid (8 bytes right)
    let tgid = (bpf_get_current_pid_tgid() >> 32) as u32; // gets tgid (8 bytes left)
    let malloc_size = ctx.arg(0).unwrap_or(0) as u32;
    let ts = bpf_ktime_get_ns();
    let cgroup_id = bpf_get_current_cgroup_id();
    if malloc_size > 0 {
        let malloc_struct = AllocInfo {
            pid: pid as u32,
            tgid: tgid as u32,
            cgroup: cgroup_id,
            size: malloc_size,
            timestamp: ts,
        };
        let key = bpf_get_current_pid_tgid();
        // info!(&ctx, "inserting malloc struct with key {} and size {}", key, malloc_size);
        MALLOC_MAP.insert(&key, &malloc_struct, 0);
    }
    Ok(())
}

#[uretprobe]
pub fn track_malloc_ret(ctx: RetProbeContext) -> u32 {
    match unsafe { try_track_malloc_ret(ctx) } {
        Ok(_) => 0,
        Err(_) => 1,
    }
}

// updates the malloc_map with the return addr of the malloc call and alloc info.
unsafe fn try_track_malloc_ret(ctx: RetProbeContext) -> Result<(), u32> {
    let addr = ctx.ret().unwrap_or(0) as u64;
    if addr == 0 {
        return Ok(());
    }
    let ts = bpf_ktime_get_ns();
    let lookup_key = bpf_get_current_pid_tgid();
    // info!(&ctx, "malloc return address {} with key {}", addr, lookup_key);
    let malloc_value = MALLOC_MAP.get(&lookup_key).unwrap_or(&AllocInfo {
        pid: 0,
        tgid: 0,
        cgroup: 0,
        size: 0,
        timestamp: 0,
    });
    if malloc_value.size == 0 {
        return Ok(());
    }

    ALLOCATED_BLOCKS_MAP.insert(&addr, malloc_value, 0);
    MALLOC_MAP.remove(&lookup_key);
    Ok(())
}

#[uprobe]
pub fn track_free(ctx: ProbeContext) -> u32 {
    match unsafe { try_track_free(ctx) } {
        Ok(_) => 0,
        Err(_) => 1,
    }
}

unsafe fn try_track_free(ctx: ProbeContext) -> Result<(), u32> {
    let free_ptr = ctx.arg(0).unwrap_or(0) as u64;
    if free_ptr == 0 {
        return Ok(());
    }
    let free_value = ALLOCATED_BLOCKS_MAP.get(&free_ptr).unwrap_or(&AllocInfo {
        pid: 0,
        tgid: 0,
        cgroup: 0,
        size: 0,
        timestamp: 0,
    });
    if free_value.size > 0 {
        ALLOCATED_BLOCKS_MAP.remove(&free_ptr);
        // info!(&ctx, "free pointer {} with size {} removed from map", free_ptr, free_value.size);
    }
    Ok(())
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
