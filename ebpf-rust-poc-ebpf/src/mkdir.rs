#![no_std]
#![no_main]

use aya_ebpf::{macros::tracepoint, programs::TracePointContext};
use aya_log_ebpf::info;

#[tracepoint]
pub fn trace_mkdir(ctx: TracePointContext) -> u32 {
    match unsafe { try_trace_mkdir(ctx) } {
        Ok(ret) => ret,
        Err(_) => 1, // Return non-zero on error
    }
}

unsafe fn try_trace_mkdir(ctx: TracePointContext) -> Result<u32, u32> {
    info!(&ctx, "mkdir syscall intercepted");
    Ok(0) // Return 0 on success
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}