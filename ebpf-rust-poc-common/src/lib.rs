#![no_std]

#[repr(C)]
#[derive(Copy, Clone)]
pub struct AllocInfo {
    pub pid: u32,
    pub tgid: u32,
    pub size: u32,
    pub cgroup: u64,
    pub timestamp: u64,
    // pub stack_id: u32,
}
// Implement aya::Pod for AllocInfo for byte serialization/deserialization
// only for userspace application is this needed
#[cfg(feature = "user")]
unsafe impl aya::Pod for AllocInfo {}
