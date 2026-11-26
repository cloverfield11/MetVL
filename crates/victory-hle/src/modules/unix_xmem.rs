//! Native macOS implementation of `xmem.dll` using Apple Silicon unified memory
//! and Mach VM zero-copy physical page aliasing (`vm_remap`).

use std::alloc::{Layout, alloc, dealloc};
use std::collections::HashMap;
use std::ffi::c_void;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::{HleModule, hle_export};

type BOOL = u32;

const PAGE: usize = 64 * 1024; // 64 KiB Scarlett page
const MIB: usize = 1024 * 1024;
const HEADER: usize = 16;

#[repr(C)]
#[derive(Default, Debug, Clone, Copy)]
pub struct BasicInformation {
    pub base_address: *mut c_void,
    pub allocation_base: *mut c_void,
    pub allocation_protect: u32,
    pub partition_id: u16,
    pub _reserved: u16,
    pub region_size: usize,
    pub state: u32,
    pub protect: u32,
    pub typ: u32,
}

#[repr(C)]
#[derive(Default, Debug, Clone, Copy)]
pub struct WorkingSet {
    pub title_limit: u64,
    pub title_used: u64,
    pub title_peak: u64,
    pub title_available: u64,
    pub title_pagefile: u64,
    pub gpu_optimal_limit: u64,
    pub gpu_optimal_used: u64,
    pub gpu_optimal_available: u64,
    pub tools_limit: u64,
    pub tools_used: u64,
}

static ALLOCATIONS: Mutex<Option<HashMap<usize, usize>>> = Mutex::new(None);
static PHYSICAL_PAGES: Mutex<Option<HashMap<usize, (usize, usize)>>> = Mutex::new(None);
static NEXT_PAGE_ID: AtomicUsize = AtomicUsize::new(1);

fn allocations() -> std::sync::MutexGuard<'static, Option<HashMap<usize, usize>>> {
    let mut lock = ALLOCATIONS.lock().unwrap_or_else(|e| e.into_inner());
    if lock.is_none() {
        *lock = Some(HashMap::new());
    }
    lock
}

fn physical_pages() -> std::sync::MutexGuard<'static, Option<HashMap<usize, (usize, usize)>>> {
    let mut lock = PHYSICAL_PAGES.lock().unwrap_or_else(|e| e.into_inner());
    if lock.is_none() {
        *lock = Some(HashMap::new());
    }
    lock
}

#[link(name = "c")]
unsafe extern "C" {
    fn mach_task_self() -> u32;
    fn vm_remap(
        target_task: u32,
        target_address: *mut usize,
        size: usize,
        mask: usize,
        flags: i32,
        src_task: u32,
        src_address: usize,
        copy: i32,
        cur_protection: *mut i32,
        max_protection: *mut i32,
        inheritance: u32,
    ) -> i32;
}

const VM_FLAGS_FIXED: i32 = 0x0000;
const VM_FLAGS_OVERWRITE: i32 = 0x4000;

pub fn map_alias(to: u64, from: u64, len: u64) -> bool {
    if len == 0 {
        return true;
    }
    let mut target = to as usize;
    let mut cur = 0;
    let mut max = 0;
    let kr = unsafe {
        vm_remap(
            mach_task_self(),
            &mut target,
            len as usize,
            0,
            VM_FLAGS_OVERWRITE | VM_FLAGS_FIXED,
            mach_task_self(),
            from as usize,
            0, // copy = FALSE: direct unified memory alias
            &mut cur,
            &mut max,
            2, // VM_INHERIT_DEFAULT
        )
    };
    kr == 0
}

pub fn map_aliases(ranges: &[(u64, u64, u64)]) -> bool {
    ranges.iter().all(|&(to, from, len)| map_alias(to, from, len))
}

pub extern "win64" fn XMemAlloc(size: usize, attributes: u64) -> *mut c_void {
    XMemAllocDefault(size, attributes)
}

pub extern "win64" fn XMemAllocDefault(size: usize, _attributes: u64) -> *mut c_void {
    let align = 64 * 1024;
    let alloc_size = (size + HEADER).next_multiple_of(align);
    let ptr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            alloc_size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_ANON | libc::MAP_PRIVATE,
            -1,
            0,
        )
    };
    if ptr == libc::MAP_FAILED {
        return std::ptr::null_mut();
    }
    let base = ptr as usize;
    allocations().as_mut().unwrap().insert(base, alloc_size);
    ptr
}

pub extern "win64" fn XMemFree(address: *mut c_void, attributes: u64) {
    XMemFreeDefault(address, attributes);
}

pub extern "win64" fn XMemFreeDefault(address: *mut c_void, _attributes: u64) {
    if address.is_null() {
        return;
    }
    let base = address as usize;
    if let Some(size) = allocations().as_mut().unwrap().remove(&base) {
        unsafe { libc::munmap(address, size) };
    }
}

pub extern "win64" fn XMemIsToolsMemAvailable() -> BOOL {
    0
}

pub extern "win64" fn XMemAllocatePhysicalPages(
    _flags: u64,
    count: *mut usize,
    pages: *mut usize,
) -> BOOL {
    if count.is_null() || pages.is_null() {
        return 0;
    }
    let n = unsafe { *count };
    let size = n * PAGE;
    let ptr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_ANON | libc::MAP_PRIVATE,
            -1,
            0,
        )
    };
    if ptr == libc::MAP_FAILED {
        return 0;
    }
    let base = ptr as usize;
    let page_id_base = NEXT_PAGE_ID.fetch_add(n, Ordering::Relaxed);
    let mut table = physical_pages();
    let map = table.as_mut().unwrap();

    for i in 0..n {
        let page_id = page_id_base + i;
        let page_addr = base + i * PAGE;
        map.insert(page_id, (page_addr, PAGE));
        unsafe { *pages.add(i) = page_id };
    }

    1
}

pub extern "win64" fn XMemFreePhysicalPages(
    _flags: u64,
    count: usize,
    pages: *const usize,
) -> BOOL {
    if pages.is_null() {
        return 0;
    }
    let mut table = physical_pages();
    let map = table.as_mut().unwrap();
    for i in 0..count {
        let page_id = unsafe { *pages.add(i) };
        if let Some((addr, size)) = map.remove(&page_id) {
            unsafe { libc::munmap(addr as *mut c_void, size) };
        }
    }
    1
}

pub extern "win64" fn XMemMapPhysicalPages(
    address: *mut c_void,
    n: usize,
    pages: *const usize,
) -> *mut c_void {
    if address.is_null() || pages.is_null() {
        return address;
    }
    let target_base = address as usize;
    let table = physical_pages();
    let map = table.as_ref().unwrap();

    for i in 0..n {
        let page_id = unsafe { *pages.add(i) };
        if let Some(&(src_addr, _)) = map.get(&page_id) {
            let target_addr = target_base + i * PAGE;
            map_alias(target_addr as u64, src_addr as u64, PAGE as u64);
        }
    }
    address
}

pub extern "win64" fn XMemMapPhysicalPagesScatter(
    addresses: *const *mut c_void,
    n: usize,
    pages: *const usize,
) -> BOOL {
    if addresses.is_null() || pages.is_null() {
        return 0;
    }
    let table = physical_pages();
    let map = table.as_ref().unwrap();

    for i in 0..n {
        let target = unsafe { *addresses.add(i) } as usize;
        let page_id = unsafe { *pages.add(i) };
        if let Some(&(src_addr, _)) = map.get(&page_id) {
            map_alias(target as u64, src_addr as u64, PAGE as u64);
        }
    }
    1
}

pub extern "win64" fn XMemVirtualAlloc(
    base: *mut c_void,
    size: usize,
    _kind: u32,
    _flags: u64,
    _protect: u32,
) -> *mut c_void {
    let size = size.next_multiple_of(16384);
    let ptr = unsafe {
        libc::mmap(
            base,
            size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_ANON | libc::MAP_PRIVATE,
            -1,
            0,
        )
    };
    if ptr == libc::MAP_FAILED {
        std::ptr::null_mut()
    } else {
        allocations().as_mut().unwrap().insert(ptr as usize, size);
        ptr
    }
}

pub extern "win64" fn XMemVirtualQuery(
    _process: *mut c_void,
    address: *const c_void,
    out: *mut BasicInformation,
) -> BOOL {
    if out.is_null() {
        return 0;
    }
    unsafe {
        (*out).base_address = address as *mut c_void;
        (*out).allocation_base = address as *mut c_void;
        (*out).allocation_protect = 0x04; // PAGE_READWRITE
        (*out).region_size = 2 * MIB;
        (*out).state = 0x1000; // MEM_COMMIT
        (*out).protect = 0x04; // PAGE_READWRITE
        (*out).typ = 0x20000; // MEM_PRIVATE
    }
    1
}

pub extern "win64" fn XMemGetWorkingSetStatistics(_which: u32, out: *mut WorkingSet) -> BOOL {
    if out.is_null() {
        return 0;
    }
    let total_ram = 16 * 1024 * MIB as u64; // 16 GB unified
    unsafe {
        (*out).title_limit = 10 * 1024 * MIB as u64;
        (*out).title_used = 2 * 1024 * MIB as u64;
        (*out).title_available = 8 * 1024 * MIB as u64;
        (*out).gpu_optimal_limit = 8 * 1024 * MIB as u64;
        (*out).gpu_optimal_used = 1024 * MIB as u64;
        (*out).gpu_optimal_available = 7 * 1024 * MIB as u64;
        (*out).title_peak = total_ram;
    }
    1
}

pub extern "win64" fn XMemTransferMemory(_kind: u32, _size: usize) -> BOOL {
    1
}

pub(crate) fn module() -> HleModule {
    HleModule {
        name: "xmem",
        dlls: &["xmem.dll"],
        exports: vec![
            hle_export!(XMemAlloc),
            hle_export!(XMemFree),
            hle_export!(XMemAllocDefault),
            hle_export!(XMemFreeDefault),
            hle_export!(XMemIsToolsMemAvailable),
            hle_export!(XMemAllocatePhysicalPages),
            hle_export!(XMemFreePhysicalPages),
            hle_export!(XMemMapPhysicalPages),
            hle_export!(XMemMapPhysicalPagesScatter),
            hle_export!(XMemVirtualAlloc),
            hle_export!(XMemVirtualQuery),
            hle_export!(XMemGetWorkingSetStatistics),
            hle_export!(XMemTransferMemory),
        ],
    }
}
