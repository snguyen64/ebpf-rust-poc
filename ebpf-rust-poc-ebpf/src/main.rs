#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{map, uprobe, uretprobe}, maps::HashMap, programs::{ProbeContext, RetProbeContext}, EbpfContext,
    helpers::{
        bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_get_current_comm, bpf_get_smp_processor_id,
        bpf_ktime_get_ns, bpf_probe_read_user, bpf_probe_read,
    }
};
use aya_log_ebpf::info;
use ebpf_rust_poc_common::AllocInfo;


#[map(name = "malloc_map")]
static mut MALLOC_MAP: HashMap<u32, u32> = HashMap::with_max_entries(1024, 0);
#[map(name = "malloc_info_map")]
static mut MALLOC_INFO_MAP: HashMap<u32, AllocInfo> = HashMap::with_max_entries(1024, 0);

#[uprobe]
pub fn track_malloc(ctx: ProbeContext) -> u32 {
    match unsafe { try_track_malloc(ctx) } {
        Ok(_) => 0,
        Err(_) => 1,
    }
}

unsafe fn try_track_malloc(ctx: ProbeContext) -> Result<(), u32> {
    // info!(&ctx, "malloc called");
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32; // Extract PID from the 64-bit value (remove TGID)
    let malloc_size = ctx.arg(0).unwrap_or(0) as u32;
    // Store the malloc pointer and size in the map
    if malloc_size > 0 {
        let malloc_value = MALLOC_MAP.get(&pid).unwrap_or(&0);
        let total_malloc_val = *malloc_value + malloc_size;
        MALLOC_MAP.insert(&pid, &total_malloc_val, 0);
        // info!(&ctx, "pid {} with size {} stored in map", pid, total_malloc_val);

        let total_malloc_value = MALLOC_INFO_MAP.get(&0).unwrap_or(&AllocInfo { size: 0, number_allocs: 0 });
        let new_size = total_malloc_value.size + malloc_size;
        let new_number_allocs = total_malloc_value.number_allocs + 1;
        let alloc_info = AllocInfo {
            size: new_size,
            number_allocs: new_number_allocs,
        };
        MALLOC_INFO_MAP.insert(&0, &alloc_info, 0);
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

unsafe fn try_track_malloc_ret(ctx: RetProbeContext) -> Result<(), u32> {
    // info!(&ctx, "malloc returned");
    // let ret_value = ctx.ret().unwrap_or(0) as usize;
    // info!(&ctx, "malloc return value: {}", ret_value);
    // if ret_value == 0 {
    //     info!(&ctx, "malloc failed");
    // } else {
    //     info!(&ctx, "malloc succeeded");
    // }
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
    // let free_ptr = ctx.pid();
    // let free_value = MALLOC_MAP.get(&free_ptr).unwrap_or(&0);
    // if *free_value > 0 {
    //     MALLOC_MAP.remove(&free_ptr);
    //     // info!(&ctx, "free pointer {} with size {} removed from map", free_ptr, *free_value);

    //     let total_malloc_value = MALLOC_INFO_MAP.get(&0).unwrap_or(&AllocInfo { size: 0, number_allocs: 0 });
    //     let new_size = total_malloc_value.size - *free_value;
    //     let new_number_allocs = total_malloc_value.number_allocs - 1;
    //     let alloc_info = AllocInfo {
    //         size: new_size,
    //         number_allocs: new_number_allocs,
    //     };
    //     MALLOC_INFO_MAP.insert(&0, &alloc_info, 0);
    // } else {
    //     // info!(&ctx, "free pointer {} not found in map", free_ptr);
    // }

    Ok(())
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
