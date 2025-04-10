#![no_std]

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AllocInfo {
    pub size: u32,
    pub number_allocs: u32,
}