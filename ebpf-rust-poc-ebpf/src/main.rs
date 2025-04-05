#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{uprobe, uretprobe},
    programs::ProbeContext,
    programs::RetProbeContext,
};
use aya_log_ebpf::info;

#[uprobe]
pub fn track_malloc(ctx: ProbeContext) -> u32 {
    match unsafe { try_track_malloc(ctx) } {
        Ok(_) => 0,
        Err(_) => 1,
    }
}

unsafe fn try_track_malloc(ctx: ProbeContext) -> Result<(), u32> {
    info!(&ctx, "malloc called");
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
    info!(&ctx, "malloc returned");
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
    info!(&ctx, "free called");
    Ok(())
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
