//! Static TLS of an executable mapped as a DLL.
//!
//! An exe always gets TLS index 0, so title code reaches its thread-local
//! block as `mov r64, gs:[0x58]` (the thread's TLS array) followed by
//! `[r64]`, without reading `_tls_index`. Mapped as a DLL, the image gets
//! another index. Every such load is turned into a call to a thunk that
//! yields `&array[index]` instead, and the image's `_tls_index` (which CRT
//! code does read, and adds to the array pointer) is set to 0.

use anyhow::{Result, bail};
use victory_pe::ImageInfo;

#[cfg(windows)]
use std::ffi::c_void;
#[cfg(windows)]
use windows_sys::Win32::System::Diagnostics::Debug::FlushInstructionCache;
#[cfg(windows)]
use windows_sys::Win32::System::Memory::{
    MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_READWRITE,
    VirtualAlloc, VirtualProtect,
};
#[cfg(windows)]
use windows_sys::Win32::System::Threading::GetCurrentProcess;

const SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const TLS64_ADDRESS_OF_INDEX: usize = 16;
/// `mov r64, gs:[0x58]` is `65 REX 8B ModRM 25 58 00 00 00`.
const LOAD_LEN: usize = 9;
const THUNK_SIZE: usize = 32;

#[cfg(not(windows))]
pub static TLS_DISP: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
#[cfg(not(windows))]
pub static TEB_DISP: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
#[cfg(not(windows))]
pub static TLS_KEY: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
#[cfg(not(windows))]
pub static TEB_KEY: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

#[cfg(not(windows))]
pub fn ensure_tls_keys() {
    use std::sync::atomic::Ordering;
    if TLS_DISP.load(Ordering::SeqCst) != 0 {
        return;
    }
    unsafe {
        let mut k1: libc::pthread_key_t = 0;
        let mut k2: libc::pthread_key_t = 0;
        if libc::pthread_key_create(&mut k1, None) == 0 {
            TLS_KEY.store(k1 as u64, Ordering::SeqCst);
            TLS_DISP.store((k1 * 8) as u32, Ordering::SeqCst);
        }
        if libc::pthread_key_create(&mut k2, None) == 0 {
            TEB_KEY.store(k2 as u64, Ordering::SeqCst);
            TEB_DISP.store((k2 * 8) as u32, Ordering::SeqCst);
        }
    }
}

#[cfg(not(windows))]
static mut MACOS_TLS_ARRAY: [*mut u8; 64] = [std::ptr::null_mut(); 64];

#[cfg(not(windows))]
#[repr(C, align(4096))]
pub struct FakeTeb {
    pub exception_list: usize, // 0x00
    pub stack_base: usize,     // 0x08
    pub stack_limit: usize,    // 0x10
    pub sub_system_tib: usize, // 0x18
    pub fiber_data: usize,     // 0x20
    pub arbitrary: usize,      // 0x28
    pub self_ptr: usize,       // 0x30
    pub env_ptr: usize,        // 0x38
    pub process_id: usize,     // 0x40
    pub thread_id: usize,      // 0x48
    pub rpc_handle: usize,     // 0x50
    pub tls_pointer: usize,    // 0x58
}

#[cfg(not(windows))]
#[derive(Clone, Copy)]
pub struct TlsTemplate {
    pub src: *const u8,
    pub raw_bytes: usize,
    pub total_bytes: usize,
    pub mod_index: usize,
}

#[cfg(not(windows))]
unsafe impl Send for TlsTemplate {}
#[cfg(not(windows))]
unsafe impl Sync for TlsTemplate {}

#[cfg(not(windows))]
pub static TLS_TEMPLATES: std::sync::Mutex<Vec<TlsTemplate>> = std::sync::Mutex::new(Vec::new());

#[cfg(not(windows))]
pub static mut FAKE_TEB: FakeTeb = FakeTeb {
    exception_list: 0,
    stack_base: 0x7fff_0000_0000,
    stack_limit: 0x7ffe_0000_0000,
    sub_system_tib: 0,
    fiber_data: 0,
    arbitrary: 0,
    self_ptr: 0,
    env_ptr: 0,
    process_id: 1000,
    thread_id: 1001,
    rpc_handle: 0,
    tls_pointer: 0,
};

#[cfg(not(windows))]
pub unsafe fn update_thread_teb() {
    let templates = {
        let guard = TLS_TEMPLATES.lock().unwrap();
        guard.clone()
    };

    let layout = std::alloc::Layout::array::<*mut u8>(64).unwrap();
    let tls_array_ptr = unsafe { std::alloc::alloc_zeroed(layout) as *mut *mut u8 };
    for t in &templates {
        let block = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                t.total_bytes,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_ANON | libc::MAP_PRIVATE,
                -1,
                0,
            )
        };
        if block != libc::MAP_FAILED {
            if t.raw_bytes > 0 && !t.src.is_null() {
                unsafe {
                    std::ptr::copy_nonoverlapping(t.src, block as *mut u8, t.raw_bytes);
                }
            }
            if t.mod_index < 64 {
                unsafe {
                    *tls_array_ptr.add(t.mod_index) = block as *mut u8;
                }
            }
        }
    }

    let stack_addr = unsafe { libc::pthread_get_stackaddr_np(libc::pthread_self()) };
    let stack_size = unsafe { libc::pthread_get_stacksize_np(libc::pthread_self()) };
    let (s_base, s_limit) = if !stack_addr.is_null() && stack_size > 0 {
        (stack_addr as usize, (stack_addr as usize).saturating_sub(stack_size))
    } else {
        (0x7fff_0000_0000, 0x7ffe_0000_0000)
    };
    let tid = unsafe { libc::pthread_mach_thread_np(libc::pthread_self()) } as usize;

    let teb = Box::into_raw(Box::new(FakeTeb {
        exception_list: 0,
        stack_base: s_base,
        stack_limit: s_limit,
        sub_system_tib: 0,
        fiber_data: 0,
        arbitrary: 0,
        self_ptr: 0,
        env_ptr: 0,
        process_id: 1000,
        thread_id: tid,
        rpc_handle: 0,
        tls_pointer: tls_array_ptr as usize,
    }));
    unsafe {
        (*teb).self_ptr = teb as usize;
    }

    ensure_tls_keys();
    let k_tls = TLS_KEY.load(std::sync::atomic::Ordering::SeqCst) as libc::pthread_key_t;
    let k_teb = TEB_KEY.load(std::sync::atomic::Ordering::SeqCst) as libc::pthread_key_t;
    if k_tls != 0 {
        unsafe {
            libc::pthread_setspecific(k_tls, tls_array_ptr as *const libc::c_void);
        }
    }
    if k_teb != 0 {
        unsafe {
            libc::pthread_setspecific(k_teb, teb as *const libc::c_void);
        }
    }

    #[cfg(target_arch = "x86_64")]
    unsafe {
        std::arch::asm!(
            "movq {0}, %gs:0x58",
            in(reg) tls_array_ptr as usize,
            options(att_syntax)
        );
        std::arch::asm!(
            "movq {0}, %gs:0x820",
            in(reg) tls_array_ptr as usize,
            options(att_syntax)
        );
        std::arch::asm!(
            "movq {0}, %gs:0x30",
            in(reg) teb as usize,
            options(att_syntax)
        );
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn victory_ensure_thread_teb() {
    unsafe {
        update_thread_teb();
    }
}

/// Redirects the image's TLS-array loads.
/// Returns the number of loads patched.
///
/// # Safety
/// `base` is the image `info` describes, mapped and not yet running.
pub(crate) unsafe fn redirect(base: usize, info: &ImageInfo) -> Result<usize> {
    let Some(tls) = &info.tls else { return Ok(0) };

    #[cfg(windows)]
    {
        // SAFETY: the TLS directory and the index it points to are in the image;
        // the OS relocated the pointer and wrote the index.
        let index_at = unsafe {
            ((base + tls.directory_rva as usize + TLS64_ADDRESS_OF_INDEX) as *const usize).read()
        } as *mut u32;
        let index = unsafe { index_at.read() };
        if index == 0 {
            return Ok(0);
        }
        let thunks = thunks(near(base, info.size_of_image as usize)?, index)?;
        let mut patched = 0;
        for section in info
            .sections
            .iter()
            .filter(|s| s.characteristics & SCN_MEM_EXECUTE != 0)
        {
            let start = base + section.rva as usize;
            let len = section.virtual_size as usize;
            let mut old = 0;
            if unsafe { VirtualProtect(start as _, len, PAGE_EXECUTE_READWRITE, &mut old) } == 0 {
                bail!("VirtualProtect(code) failed: {}", std::io::Error::last_os_error());
            }
            let code = unsafe { std::slice::from_raw_parts_mut(start as *mut u8, len) };
            patched += patch(code, start, thunks);
            unsafe {
                VirtualProtect(start as _, len, old, &mut old);
                FlushInstructionCache(GetCurrentProcess(), start as _, len);
            }
        }
        unsafe { index_at.write(0) };
        tracing::info!(index, patched, "static TLS redirected");
        Ok(patched)
    }

    #[cfg(not(windows))]
    {
        static NEXT_TLS_INDEX: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let mod_index = NEXT_TLS_INDEX.fetch_add(1, std::sync::atomic::Ordering::SeqCst) as usize;

        // 1. Register TLS template on macOS
        let dir = (base + tls.directory_rva as usize) as *const u8;
        let start_va = unsafe { (dir as *const u64).read() } as usize;
        let end_va = unsafe { (dir.add(8) as *const u64).read() } as usize;
        let zero_fill = unsafe { (dir.add(32) as *const u32).read() } as usize;
        let raw_bytes = if end_va > start_va { end_va - start_va } else { 0 };
        let total_bytes = (raw_bytes + zero_fill).next_multiple_of(4096).max(4096);

        let src = if raw_bytes > 0 && start_va > 0 {
            if start_va >= base {
                start_va as *const u8
            } else {
                (base + start_va) as *const u8
            }
        } else {
            std::ptr::null()
        };

        TLS_TEMPLATES.lock().unwrap().push(TlsTemplate {
            src,
            raw_bytes,
            total_bytes,
            mod_index,
        });

        unsafe {
            update_thread_teb();
        }

        // Set index_at to mod_index
        if tls.directory_rva != 0 {
            let index_at_ptr = unsafe {
                ((base + tls.directory_rva as usize + TLS64_ADDRESS_OF_INDEX) as *const usize).read()
            } as *mut u32;
            if !index_at_ptr.is_null() {
                unsafe { *index_at_ptr = mod_index as u32; }
            }
        }

        ensure_tls_keys();
        // 2. Generate thunks that return &MACOS_TLS_ARRAY
        let thunks = thunks(near(base, info.size_of_image as usize)?, 0)?;

        // 3. Patch every executable section
        let mut patched = 0;
        for section in info
            .sections
            .iter()
            .filter(|s| s.characteristics & SCN_MEM_EXECUTE != 0)
        {
            let start = base + section.rva as usize;
            let len = section.virtual_size as usize;
            let aligned_start = start & !4095;
            let aligned_len = (start + len - aligned_start).next_multiple_of(4096);

            let ok = unsafe {
                libc::mprotect(
                    aligned_start as *mut libc::c_void,
                    aligned_len,
                    libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
                )
            };
            if ok != 0 {
                bail!("mprotect(code) failed: {}", std::io::Error::last_os_error());
            }

            let code = unsafe { std::slice::from_raw_parts_mut(start as *mut u8, len) };
            patched += patch(code, start, thunks);

            unsafe {
                libc::mprotect(
                    aligned_start as *mut libc::c_void,
                    aligned_len,
                    libc::PROT_READ | libc::PROT_EXEC,
                );
            }
        }
        tracing::info!(patched, "static TLS redirected for macOS");
        Ok(patched)
    }
}

/// Rewrites each `mov r64, gs:[0x58]` in `code` (at address `at`) as
/// `call thunks[r]; nop4`, and `mov r64, gs:[0x30]` as `call teb_thunks[r]; nop4`.
/// `thunks` must be within 2 GiB of `code`.
fn patch(code: &mut [u8], at: usize, thunks: usize) -> usize {
    let mut count = 0;
    let mut i = 0;
    while i + LOAD_LEN <= code.len() {
        let c = &code[i..i + LOAD_LEN];
        let rex = c[1];
        let reg = usize::from((c[3] >> 3) & 7) | if rex & 4 != 0 { 8 } else { 0 };
        #[cfg(not(windows))]
        {
            let tls_disp = TLS_DISP.load(std::sync::atomic::Ordering::SeqCst);
            let teb_disp = TEB_DISP.load(std::sync::atomic::Ordering::SeqCst);
            if tls_disp != 0 && c[4..] == [0x25, 0x58, 0, 0, 0] {
                code[i + 5..i + 9].copy_from_slice(&tls_disp.to_le_bytes());
                count += 1;
                i += LOAD_LEN;
                continue;
            } else if teb_disp != 0 && c[4..] == [0x25, 0x30, 0, 0, 0] {
                code[i + 5..i + 9].copy_from_slice(&teb_disp.to_le_bytes());
                count += 1;
                i += LOAD_LEN;
                continue;
            }
        }

        if c[0] == 0x65
            && (rex == 0x48 || rex == 0x4C)
            && c[2] == 0x8B
            && c[3] & 0xC7 == 0x04
            && reg != 4
        {
            let target = if c[4..] == [0x25, 0x58, 0, 0, 0] {
                // mov r64, gs:[0x58] -> TLS array
                Some(thunks + reg * THUNK_SIZE)
            } else if c[4..] == [0x25, 0x30, 0, 0, 0] {
                // mov r64, gs:[0x30] -> TEB pointer
                Some(thunks + 512 + reg * THUNK_SIZE)
            } else {
                None
            };

            if let Some(target_thunk) = target {
                let rel = target_thunk as i64 - (at + i + 5) as i64;
                code[i] = 0xE8;
                code[i + 1..i + 5].copy_from_slice(&(rel as i32).to_le_bytes());
                code[i + 5..i + 9].copy_from_slice(&[0x0F, 0x1F, 0x40, 0x00]);
                count += 1;
                i += LOAD_LEN;
                continue;
            }
        }
        i += 1;
    }
    count
}

#[cfg(windows)]
fn thunks(block: *mut u8, index: u32) -> Result<usize> {
    let disp = (index * 8).to_le_bytes();
    for reg in 0..16u8 {
        let (r, low) = (reg >> 3, reg & 7);
        let mut code = vec![0x65, 0x48 | r << 2, 0x8B, low << 3 | 4, 0x25, 0x58, 0, 0, 0];
        code.extend([0x48 | r << 2 | r, 0x8D, 0x80 | low << 3 | low]);
        if low == 4 {
            code.push(0x24); // SIB: [r12 + disp32]
        }
        code.extend(disp);
        code.push(0xC3);
        unsafe {
            std::ptr::copy_nonoverlapping(
                code.as_ptr(),
                block.add(usize::from(reg) * THUNK_SIZE),
                code.len(),
            )
        };
    }
    let mut old = 0;
    if unsafe { VirtualProtect(block as _, 4096, PAGE_EXECUTE_READ, &mut old) } == 0 {
        bail!(
            "VirtualProtect(TLS thunks) failed: {}",
            std::io::Error::last_os_error()
        );
    }
    Ok(block as usize)
}

#[cfg(not(windows))]
fn thunks(block: *mut u8, _index: u32) -> Result<usize> {
    let tls_disp = TLS_DISP.load(std::sync::atomic::Ordering::SeqCst).to_le_bytes();
    let teb_disp = TEB_DISP.load(std::sync::atomic::Ordering::SeqCst).to_le_bytes();
    for reg in 0..16u8 {
        let (r, low) = (reg >> 3, reg & 7);
        // 1. TLS array thunk (offset reg * 32): mov reg, gs:[tls_disp]; ret
        let mut code = vec![0x65, 0x48 | (r << 2), 0x8B, (low << 3) | 4, 0x25];
        code.extend_from_slice(&tls_disp);
        code.push(0xC3);
        unsafe {
            std::ptr::copy_nonoverlapping(
                code.as_ptr(),
                block.add(usize::from(reg) * THUNK_SIZE),
                code.len(),
            );
        }

        // 2. TEB thunk (offset 512 + reg * 32): mov reg, gs:[teb_disp]; ret
        let mut code_teb = vec![0x65, 0x48 | (r << 2), 0x8B, (low << 3) | 4, 0x25];
        code_teb.extend_from_slice(&teb_disp);
        code_teb.push(0xC3);
        unsafe {
            std::ptr::copy_nonoverlapping(
                code_teb.as_ptr(),
                block.add(512 + usize::from(reg) * THUNK_SIZE),
                code_teb.len(),
            );
        }
    }

    if unsafe { libc::mprotect(block as _, 4096, libc::PROT_READ | libc::PROT_EXEC) } != 0 {
        bail!("mprotect(TLS thunks) failed: {}", std::io::Error::last_os_error());
    }
    Ok(block as usize)
}

#[cfg(windows)]
fn near(base: usize, size: usize) -> Result<*mut u8> {
    const GRANULE: usize = 0x1_0000;
    if size >= 1 << 30 {
        bail!("image too large for TLS thunks within rel32 reach");
    }
    let above = (base + size).next_multiple_of(GRANULE);
    for k in 0..(1usize << 14) {
        for hint in [
            base.checked_sub((k + 1) * GRANULE),
            Some(above + k * GRANULE),
        ] {
            let Some(hint) = hint else { continue };
            let p = unsafe {
                VirtualAlloc(
                    hint as *const c_void,
                    4096,
                    MEM_COMMIT | MEM_RESERVE,
                    PAGE_READWRITE,
                )
            };
            if !p.is_null() {
                return Ok(p.cast());
            }
        }
    }
    bail!("no free page near the image for TLS thunks")
}

#[cfg(not(windows))]
fn near(base: usize, size: usize) -> Result<*mut u8> {
    const GRANULE: usize = 0x1_0000;
    if size >= 1 << 30 {
        bail!("image too large for TLS thunks within rel32 reach");
    }
    let above = (base + size).next_multiple_of(GRANULE);
    for k in 0..(1usize << 14) {
        for hint in [
            base.checked_sub((k + 1) * GRANULE),
            Some(above + k * GRANULE),
        ] {
            let Some(hint) = hint else { continue };
            let p = unsafe {
                libc::mmap(
                    hint as *mut libc::c_void,
                    4096,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                )
            };
            if p != libc::MAP_FAILED {
                let diff = (p as usize).abs_diff(base);
                if diff < 0x7000_0000 {
                    return Ok(p.cast());
                } else {
                    unsafe { libc::munmap(p, 4096); }
                }
            }
        }
    }
    bail!("no free page near the image for TLS thunks")
}
