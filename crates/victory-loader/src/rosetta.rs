//! Apple Silicon Rosetta 2 workaround for AVX/AVX2 masked loads and stores
//! (`vpmaskmovd`, `vpmaskmovq`, `vmaskmovps`, `vmaskmovpd`).
//!
//! On real x86-64 hardware, masked-off lanes in `vpmaskmov*` / `vmaskmov*`
//! suppress page faults. Rosetta 2 translates a 128-bit or 256-bit masked load
//! or store into an unmasked memory access and expects to recover from page
//! faults via `EmulateForward`, which aborts when an instruction crosses an
//! unmapped or guarded page boundary:
//! `rosetta error: unexpectedly need to EmulateForward on a synchronous exception`.
//!
//! Since every such instruction is at least 5 bytes (3-byte VEX + opcode +
//! ModRM), we replace each occurrence in executable sections with a 5-byte
//! relative `call rel32` to a tiny generated thunk that computes the effective
//! address (`lea`) and performs the per-lane scalar load/store only for lanes
//! whose sign bit is set in the mask register.

use anyhow::{Result, bail};
use victory_pe::ImageInfo;
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

static DUMMY_RESOURCE_VA: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

unsafe fn neutralize_watchdogs(base: usize, info: &ImageInfo) {
    let mut total = 0;
    let mut total_asserts = 0;
        for section in info
        .sections
        .iter()
        .filter(|s| s.characteristics & SCN_MEM_EXECUTE != 0)
    {
        let start = base + section.rva as usize;
        let len = section.virtual_size as usize;
        #[cfg(windows)]
        unsafe {
            let mut old = 0;
            if VirtualProtect(start as _, len, PAGE_EXECUTE_READWRITE, &mut old) != 0 {
                let slice = std::slice::from_raw_parts_mut(start as *mut u8, len);
                let mut i = 0;
                while i + 2 < slice.len() {
                    if slice[i] >= 0x70 && slice[i] <= 0x7f && slice[i + 1] == 0x01 && slice[i + 2] == 0xcc {
                        slice[i + 2] = 0x90;
                        total_asserts += 1;
                        i += 3;
                    } else if i + 11 <= slice.len() && slice[i..i + 7] == [0xc7, 0x04, 0x25, 0x00, 0x00, 0x00, 0x00] {
                        let len = if i + 12 <= slice.len() && slice[i + 11] == 0xcc { 12 } else { 11 };
                        slice[i..i + len].fill(0x90);
                        slice[i] = 0xc3; // ret
                        total += 1;
                        i += len;

                    } else {
                        i += 1;
                    }
                }
                VirtualProtect(start as _, len, old, &mut old);
                FlushInstructionCache(GetCurrentProcess(), start as _, len);
            }
        }
        #[cfg(not(windows))]
        unsafe {
            let aligned_start = start & !4095;
            let aligned_len = (start + len - aligned_start).next_multiple_of(4096);
            if libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) == 0 {
                let slice = std::slice::from_raw_parts_mut(start as *mut u8, len);
                let mut i = 0;
                while i + 2 < slice.len() {
                    if slice[i] >= 0x70 && slice[i] <= 0x7f && slice[i + 1] == 0x01 && slice[i + 2] == 0xcc {
                        slice[i + 2] = 0x90;
                        total_asserts += 1;
                        i += 3;
                    } else if i + 11 <= slice.len() && slice[i..i + 7] == [0xc7, 0x04, 0x25, 0x00, 0x00, 0x00, 0x00] {
                        let len = if i + 12 <= slice.len() && slice[i + 11] == 0xcc { 12 } else { 11 };
                        slice[i..i + len].fill(0x90);
                        slice[i] = 0xc3; // ret
                        total += 1;
                        i += len;

                    } else {
                        i += 1;
                    }
                }
                libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_EXEC);
            }
        }
    }
    if total > 0 {
        tracing::info!(total, "neutralized intentional mov [0], imm32 hardcrash watchdog aborts");
    }
    if total_asserts > 0 {
        tracing::info!(total_asserts, "neutralized developer j<cond> +1; int3 assertion traps to nops");
    }
}

unsafe fn patch_telemetry_map(base: usize, info: &ImageInfo) {
    let target_rva = 0x55fee40;
    let target_site = base + target_rva;
    if target_rva + 5 >= info.size_of_image as usize {
        return;
    }
    let slice = unsafe { std::slice::from_raw_parts(target_site as *const u8, 5) };
    if slice != [0x48, 0x89, 0x5c, 0x24, 0x10] {
        return;
    }
    let thunk_mem = match alloc_near(base, info.size_of_image as usize, 4096) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(error = %e, "failed to allocate thunk page for telemetry map fix");
            return;
        }
    };
    let thunk_va = thunk_mem as usize;
    let dummy_node_va = thunk_va + 0x40;
    let dummy_map_va = thunk_va + 0xa0;

    let mut code = Vec::with_capacity(176);
    // 0x00: test rcx, rcx
    code.extend_from_slice(&[0x48, 0x85, 0xc9]);
    // 0x03: jz .Lfixup (to 0x0d, rel = +8)
    code.extend_from_slice(&[0x74, 0x08]);
    // 0x05: mov rax, [rcx]
    code.extend_from_slice(&[0x48, 0x8b, 0x01]);
    // 0x08: test rax, rax
    code.extend_from_slice(&[0x48, 0x85, 0xc0]);
    // 0x0b: jnz .Lgood (to 0x26, rel = +0x19)
    code.extend_from_slice(&[0x75, 0x19]);
    // 0x0d: .Lfixup: test r14, r14
    code.extend_from_slice(&[0x4d, 0x85, 0xf6]);
    // 0x10: jz .Ldummy (to 0x1f, rel = +0x0d)
    code.extend_from_slice(&[0x74, 0x0d]);
    // 0x12: mov rax, [r14]
    code.extend_from_slice(&[0x49, 0x8b, 0x06]);
    // 0x15: test rax, rax
    code.extend_from_slice(&[0x48, 0x85, 0xc0]);
    // 0x18: jz .Ldummy (to 0x1f, rel = +0x05)
    code.extend_from_slice(&[0x74, 0x05]);
    // 0x1a: mov rcx, r14
    code.extend_from_slice(&[0x4c, 0x89, 0xf1]);
    // 0x1d: jmp .Lgood (to 0x26, rel = +0x07)
    code.extend_from_slice(&[0xeb, 0x07]);
    // 0x1f: .Ldummy: lea rcx, [rip + disp32] (to dummy_map_va at 0xa0)
    let disp32: i32 = (0xa0 - 0x26) as i32;
    code.extend_from_slice(&[0x48, 0x8d, 0x0d]);
    code.extend_from_slice(&disp32.to_le_bytes());
    // 0x26: .Lgood: mov [rsp+0x10], rbx (replaced instruction)
    code.extend_from_slice(&[0x48, 0x89, 0x5c, 0x24, 0x10]);
    // 0x2b: jmp rel32 (target_site + 5)
    let ret_disp32: i32 = ((target_site + 5) as i64 - (thunk_va + 0x30) as i64) as i32;
    code.push(0xe9);
    code.extend_from_slice(&ret_disp32.to_le_bytes());

    // Pad to 0x40
    code.resize(0x40, 0);

    // 0x40: dummy_node (96 bytes)
    code.extend_from_slice(&(dummy_node_va as u64).to_le_bytes()); // left
    code.extend_from_slice(&(dummy_node_va as u64).to_le_bytes()); // parent
    code.extend_from_slice(&(dummy_node_va as u64).to_le_bytes()); // right
    code.push(0x01); // color = 1 (black)
    code.push(0x01); // isnil = 1
    code.resize(0xa0, 0); // pad dummy_node to 96 bytes

    // 0xa0: dummy_map (16 bytes)
    code.extend_from_slice(&(dummy_node_va as u64).to_le_bytes()); // head
    code.extend_from_slice(&0u64.to_le_bytes()); // size = 0
    code.resize(4096, 0);

    unsafe {
        std::ptr::copy_nonoverlapping(code.as_ptr(), thunk_mem, code.len());

        #[cfg(not(windows))]
        {
            libc::mprotect(thunk_mem as *mut libc::c_void, 4096, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC);
            let aligned_start = target_site & !4095;
            let aligned_len = (target_site + 5 - aligned_start).next_multiple_of(4096);
            if libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) == 0 {
                let patch_disp: i32 = (thunk_va as i64 - (target_site + 5) as i64) as i32;
                let target_slice = std::slice::from_raw_parts_mut(target_site as *mut u8, 5);
                target_slice[0] = 0xe9; // jmp rel32
                target_slice[1..5].copy_from_slice(&patch_disp.to_le_bytes());
                libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_EXEC);
                tracing::info!(target_site = format_args!("{:#x}", target_site), thunk_va = format_args!("{:#x}", thunk_va), "patched std::map insert nil-deref guard for title worker");
            }
        }
        #[cfg(windows)]
        {
            let mut old = 0;
            VirtualProtect(thunk_mem.cast(), 4096, PAGE_EXECUTE_READWRITE, &mut old);
            if VirtualProtect(target_site as _, 5, PAGE_EXECUTE_READWRITE, &mut old) != 0 {
                let patch_disp: i32 = (thunk_va as i64 - (target_site + 5) as i64) as i32;
                let target_slice = std::slice::from_raw_parts_mut(target_site as *mut u8, 5);
                target_slice[0] = 0xe9;
                target_slice[1..5].copy_from_slice(&patch_disp.to_le_bytes());
                VirtualProtect(target_site as _, 5, old, &mut old);
                FlushInstructionCache(GetCurrentProcess(), target_site as _, 5);
            }
        }
    }
}

unsafe fn patch_rpf_null_device(base: usize, info: &ImageInfo) {
    let target_rva = 0xfc23bd;
    let target_site = base + target_rva;
    if target_rva + 14 >= info.size_of_image as usize {
        return;
    }
    // Verify target sequence:
    // 0x140fc23bd: mov qword ptr [rsi + 0x18], rax (48 89 46 18)
    // 0x140fc23c1: cmp rax, -1 (48 83 f8 ff)
    // 0x140fc23c5: je 0x140fc2474 (0f 84 a9 00 00 00)
    let slice = unsafe { std::slice::from_raw_parts(target_site as *const u8, 14) };
    if slice[0..4] != [0x48, 0x89, 0x46, 0x18] || slice[4..8] != [0x48, 0x83, 0xf8, 0xff] {
        return;
    }

    #[cfg(unix)]
    unsafe {
        let aligned_start = target_site & !4095;
        let aligned_len = (target_site + 14 - aligned_start).next_multiple_of(4096);
        if libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) == 0 {
            let target_mut = std::slice::from_raw_parts_mut(target_site as *mut u8, 14);
            // Replace `cmp rax, -1` (4 bytes: 48 83 f8 ff) with `test rax, rax; nop` (48 85 c0 90)
            // If rax == 0 (null device or invalid handle), je triggers and aborts mounting safely instead of null-deref
            target_mut[4] = 0x48;
            target_mut[5] = 0x85;
            target_mut[6] = 0xc0;
            target_mut[7] = 0x90; // nop
            libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_EXEC);
            tracing::info!(target_site = format_args!("{:#x}", target_site), "patched RPF null device check to prevent null-deref crash");
        }
    }
}

unsafe fn patch_rpf_mount_guard(base: usize, info: &ImageInfo) {
    let target_rva = 0x2237320;
    let target_site = base + target_rva;
    if target_rva + 12 >= info.size_of_image as usize {
        return;
    }
    // Verify target sequence:
    // 0x142237320: mov rax, qword ptr [rbx]       (48 8b 03)
    // 0x142237323: mov rcx, rbx                   (48 89 d9)
    // 0x142237326: call qword ptr [rax + 0x3b8]   (ff 90 b8 03 00 00)
    let slice = unsafe { std::slice::from_raw_parts(target_site as *const u8, 12) };
    if slice != [0x48, 0x8b, 0x03, 0x48, 0x89, 0xd9, 0xff, 0x90, 0xb8, 0x03, 0x00, 0x00] {
        return;
    }

    #[cfg(unix)]
    unsafe {
        let aligned_start = target_site & !4095;
        let aligned_len = (target_site + 12 - aligned_start).next_multiple_of(4096);
        if libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) == 0 {
            let target_mut = std::slice::from_raw_parts_mut(target_site as *mut u8, 12);
            // Replace with:
            // 48 85 db             test rbx, rbx
            // 0f 84 31 01 00 00    jz 0x14223745a (disp = +0x131 to release and clean up rdi)
            // 90 90 90             nop nop nop
            let cleanup_target = base + 0x223745a;
            let disp: i32 = (cleanup_target as i64 - (target_site + 3 + 6) as i64) as i32;
            target_mut[0] = 0x48;
            target_mut[1] = 0x85;
            target_mut[2] = 0xdb;
            target_mut[3] = 0x0f;
            target_mut[4] = 0x84;
            target_mut[5..9].copy_from_slice(&disp.to_le_bytes());
            target_mut[9] = 0x90;
            target_mut[10] = 0x90;
            target_mut[11] = 0x90;
            libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_EXEC);
            tracing::info!(target_site = format_args!("{:#x}", target_site), "patched RPF mount nil-rbx guard to release and proceed");
        }
    }
}

unsafe fn patch_gameconfig_watchdog(base: usize, info: &ImageInfo) {
    let target_rva = 0x2224517;
    let target_site = base + target_rva;
    if target_rva >= info.size_of_image as usize {
        return;
    }
    let slice = unsafe { std::slice::from_raw_parts(target_site as *const u8, 1) };
    if slice[0] != 0xcc {
        return;
    }

    #[cfg(unix)]
    unsafe {
        let aligned_start = target_site & !4095;
        let aligned_len = (target_site + 1 - aligned_start).next_multiple_of(4096);
        if libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) == 0 {
            let target_mut = std::slice::from_raw_parts_mut(target_site as *mut u8, 1);
            target_mut[0] = 0x90; // nop out assertion int3 so execution falls through to clean epilogue ret
            libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_EXEC);
            tracing::info!(target_site = format_args!("{:#x}", target_site), "patched gameconfig assertion int3 -> nop to allow clean epilogue return");
        }
    }
}

unsafe fn patch_config_version_guard(base: usize, info: &ImageInfo) {
    let target_rva = 0x1d5cc60;
    let target_site = base + target_rva;
    if target_rva + 16 >= info.size_of_image as usize {
        return;
    }
    // Verify target sequence:
    // 0x141d5cc60: mov eax, ecx; cmp cx, 0x3e7; ja 0x141d5cc6a; int3; add eax, 5; ret
    let slice = unsafe { std::slice::from_raw_parts(target_site as *const u8, 14) };
    if slice[0..10] != [0x89, 0xc8, 0x66, 0x81, 0xf9, 0xe7, 0x03, 0x77, 0x01, 0xcc] {
        return;
    }

    #[cfg(unix)]
    unsafe {
        let aligned_start = target_site & !4095;
        let aligned_len = (target_site + 16 - aligned_start).next_multiple_of(4096);
        if libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) == 0 {
            let target_mut = std::slice::from_raw_parts_mut(target_site as *mut u8, 16);
            // Replace with:
            // mov eax, 0x3ed (1005)
            // cmp cx, 0x3e7
            // jbe .Lret (+3)
            // lea eax, [rcx + 5]
            // .Lret: ret
            let patch: [u8; 16] = [
                0xb8, 0xed, 0x03, 0x00, 0x00, // mov eax, 0x3ed
                0x66, 0x81, 0xf9, 0xe7, 0x03, // cmp cx, 0x3e7
                0x76, 0x03,                   // jbe +3
                0x8d, 0x41, 0x05,             // lea eax, [rcx + 5]
                0xc3,                         // ret
            ];
            target_mut.copy_from_slice(&patch);
            libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_EXEC);
            tracing::info!(target_site = format_args!("{:#x}", target_site), "patched config version guard to safely default to 1000 without int3 abort");
        }
    }
}

unsafe fn patch_vcall_epilogue_watchdog(base: usize, info: &ImageInfo) {
    let target_rva = 0x2219650;
    let target_site = base + target_rva;
    if target_rva >= info.size_of_image as usize {
        return;
    }
    let slice = unsafe { std::slice::from_raw_parts(target_site as *const u8, 1) };
    if slice[0] != 0xcc {
        return;
    }

    #[cfg(unix)]
    unsafe {
        let aligned_start = target_site & !4095;
        let aligned_len = (target_site + 1 - aligned_start).next_multiple_of(4096);
        if libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) == 0 {
            let target_mut = std::slice::from_raw_parts_mut(target_site as *mut u8, 1);
            target_mut[0] = 0x90; // nop out int3 watchdog after vcall to allow unlocking mutex and returning
            libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_EXEC);
            tracing::info!(target_site = format_args!("{:#x}", target_site), "patched vcall epilogue int3 -> nop to unlock mutex and return");
        }
    }
}

unsafe fn patch_vcall_bypass(base: usize, info: &ImageInfo) {
    let target_rva = 0x4fac3e5;
    let target_site = base + target_rva;
    if target_rva + 2 >= info.size_of_image as usize {
        return;
    }
    let slice = unsafe { std::slice::from_raw_parts(target_site as *const u8, 2) };
    if slice != [0x74, 0x0a] {
        return;
    }

    #[cfg(unix)]
    unsafe {
        let aligned_start = target_site & !4095;
        let aligned_len = (target_site + 2 - aligned_start).next_multiple_of(4096);
        if libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) == 0 {
            let target_mut = std::slice::from_raw_parts_mut(target_site as *mut u8, 2);
            target_mut[0] = 0x90; // nop
            target_mut[1] = 0x90; // nop
            libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_EXEC);
            tracing::info!(target_site = format_args!("{:#x}", target_site), "patched vcall branch 0x74 0x0a -> nop nop to safely return without invalid vcall dispatch");
        }
    }
}

unsafe fn patch_gameconfig_version_call(base: usize, info: &ImageInfo) {
    let target_rva = 0x2240ef7;
    let target_site = base + target_rva;
    if target_rva + 5 >= info.size_of_image as usize {
        return;
    }
    let slice = unsafe { std::slice::from_raw_parts(target_site as *const u8, 5) };
    if slice != [0xe8, 0xf4, 0x88, 0x8e, 0x03] {
        return;
    }

    #[cfg(unix)]
    unsafe {
        let aligned_start = target_site & !4095;
        let aligned_len = (target_site + 5 - aligned_start).next_multiple_of(4096);
        if libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) == 0 {
            let target_mut = std::slice::from_raw_parts_mut(target_site as *mut u8, 5);
            target_mut.fill(0x90); // nop out call to 0x145b297f0
            libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_EXEC);
            tracing::info!(target_site = format_args!("{:#x}", target_site), "patched gameconfig version call e8 ... -> nop(5) to avoid nil-object array resize");
        }
    }
}

unsafe fn patch_clwb(base: usize, info: &ImageInfo) {
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
        #[cfg(unix)]
        unsafe {
            if libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) == 0 {
                let slice = std::slice::from_raw_parts_mut(start as *mut u8, len);
                let mut i = 0;
                while i + 4 <= slice.len() {
                    if slice[i] == 0x66 && slice[i + 1] == 0x0f && slice[i + 2] == 0xae && (0x30..=0x37).contains(&slice[i + 3]) {
                        slice[i..i + 4].fill(0x90);
                        patched += 1;
                        i += 4;
                    } else if i + 5 <= slice.len() && slice[i] == 0x66 && (0x40..=0x4f).contains(&slice[i + 1]) && slice[i + 2] == 0x0f && slice[i + 3] == 0xae && (0x30..=0x37).contains(&slice[i + 4]) {
                        slice[i..i + 5].fill(0x90);
                        patched += 1;
                        i += 5;
                    } else {
                        i += 1;
                    }
                }
                libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_EXEC);
            }
        }
    }
    if patched > 0 {
        tracing::info!(patched, "clwb instructions patched for Apple Silicon / Rosetta 2");
    }
}

unsafe fn patch_hash_null_guard(base: usize, info: &ImageInfo) {
    let target_rva = 0x4db9200;
    let target_site = base + target_rva;
    if target_rva + 16 >= info.size_of_image as usize {
        return;
    }
    let slice = unsafe { std::slice::from_raw_parts(target_site as *const u8, 16) };
    if slice != [
        0x41, 0x57, 0x41, 0x56, 0x41, 0x55, 0x41, 0x54, 0x56, 0x57, 0x55, 0x53, 0x48, 0x83, 0xec, 0x78,
    ] {
        return;
    }

    let thunk_mem = match alloc_near(base, info.size_of_image as usize, 4096) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(error = %e, "failed to allocate thunk page for hash null guard");
            return;
        }
    };
    let thunk_va = thunk_mem as usize;

    let mut thunk = Vec::with_capacity(64);
    thunk.extend_from_slice(&[0x48, 0x85, 0xc9]); // 0..3: test rcx, rcx
    thunk.extend_from_slice(&[0x74, 26]);         // 3..5: jz .Lzero (offset 31)
    thunk.extend_from_slice(&[0x48, 0x85, 0xd2]); // 5..8: test rdx, rdx
    thunk.extend_from_slice(&[0x74, 21]);         // 8..10: jz .Lzero (offset 31)
    thunk.extend_from_slice(&[
        0x41, 0x57, 0x41, 0x56, 0x41, 0x55, 0x41, 0x54, 0x56, 0x57, 0x55, 0x53, 0x48, 0x83, 0xec, 0x78,
    ]); // 10..26: original preamble
    let return_site = target_site + 16;
    let next_ip = thunk_va + 26 + 5;
    let disp = (return_site as i64 - next_ip as i64) as i32;
    thunk.push(0xe9);
    thunk.extend_from_slice(&disp.to_le_bytes()); // 26..31: jmp return_site
    thunk.extend_from_slice(&[0x31, 0xc0, 0xc3]); // 31..34: xor eax, eax; ret

    #[cfg(unix)]
    unsafe {
        std::ptr::copy_nonoverlapping(thunk.as_ptr(), thunk_mem, thunk.len());
        libc::mprotect(thunk_mem as *mut libc::c_void, 4096, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC);
        let aligned_start = target_site & !4095;
        let aligned_len = (target_site + 16 - aligned_start).next_multiple_of(4096);
        if libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) == 0 {
            let target_mut = std::slice::from_raw_parts_mut(target_site as *mut u8, 16);
            let disp = (thunk_va as i64 - (target_site as i64 + 5)) as i32;
            target_mut[0] = 0xe9;
            target_mut[1..5].copy_from_slice(&disp.to_le_bytes());
            target_mut[5..16].fill(0x90);
            libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_EXEC);
            tracing::info!(target_site = format_args!("{:#x}", target_site), thunk_va = format_args!("{:#x}", thunk_va), "patched hash null guard trampoline");
        }
    }
}

unsafe fn patch_null_assert_traps(base: usize, info: &ImageInfo) {
    let trap_rva = 0x22106e0;
    if trap_rva < info.size_of_image as usize {
        let target_site = base + trap_rva;
        let slice = unsafe { std::slice::from_raw_parts(target_site as *const u8, 1) };
        if slice[0] == 0xcc {
            #[cfg(unix)]
            unsafe {
                let aligned_start = target_site & !4095;
                let aligned_len = (target_site + 1 - aligned_start).next_multiple_of(4096);
                if libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) == 0 {
                    let target_mut = std::slice::from_raw_parts_mut(target_site as *mut u8, 1);
                    target_mut[0] = 0xc3; // ret
                    libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_EXEC);
                    tracing::info!(target_site = format_args!("{:#x}", target_site), "patched assert trap int3 -> ret");
                }
            }
        }
    }

    let fn_rva = 0x2a34c0;
    if fn_rva < info.size_of_image as usize {
        let target_site = base + fn_rva;
        let slice = unsafe { std::slice::from_raw_parts(target_site as *const u8, 1) };
        if slice[0] == 0xe9 {
            #[cfg(unix)]
            unsafe {
                let aligned_start = target_site & !4095;
                let aligned_len = (target_site + 1 - aligned_start).next_multiple_of(4096);
                if libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) == 0 {
                    let target_mut = std::slice::from_raw_parts_mut(target_site as *mut u8, 1);
                    target_mut[0] = 0xc3; // ret
                    libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_EXEC);
                    tracing::info!(target_site = format_args!("{:#x}", target_site), "patched assert_non_null jmp -> ret");
                }
            }
        }
    }

    // 0x140f1f4d5: hashtable / dictionary empty lookup trap
    // When table capacity is 0 or element not found, engine branches to 0x140f1f4d5 (int3).
    // We replace it with: xor eax, eax; add rsp, 0x28; pop rbx; pop rsi; ret
    let dict_trap_rva = 0x0f1f4d5;
    if dict_trap_rva + 9 < info.size_of_image as usize {
        let target_site = base + dict_trap_rva;
        let slice = unsafe { std::slice::from_raw_parts(target_site as *const u8, 2) };
        if slice == [0xcc, 0xcc] {
            #[cfg(unix)]
            unsafe {
                let aligned_start = target_site & !4095;
                let aligned_len = (target_site + 9 - aligned_start).next_multiple_of(4096);
                if libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) == 0 {
                    let target_mut = std::slice::from_raw_parts_mut(target_site as *mut u8, 9);
                    // 31 c0 48 83 c4 28 5b 5e c3
                    target_mut.copy_from_slice(&[0x31, 0xc0, 0x48, 0x83, 0xc4, 0x28, 0x5b, 0x5e, 0xc3]);
                    libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_EXEC);
                    tracing::info!(target_site = format_args!("{:#x}", target_site), "patched dict lookup int3 -> safe return (xor eax, eax; add rsp, 0x28; pop rbx; pop rsi; ret)");
                }
            }
        }
    }

    // Neutralize developer assert int3 traps before error/recovery epilogues
    let assert_rvas: &[usize] = &[
        0x25a4ca0, // title-worker-101 loop assertion
        0x034c0bd,
        0x1957185,
        0x19572ec,
        0x2425df4,
        0x31df357,
        0x43a657e,
        0x43ad94e,
    ];
    for &arva in assert_rvas {
        if arva < info.size_of_image as usize {
            let target_site = base + arva;
            let slice = unsafe { std::slice::from_raw_parts(target_site as *const u8, 1) };
            if slice[0] == 0xcc {
                #[cfg(unix)]
                unsafe {
                    let aligned_start = target_site & !4095;
                    let aligned_len = (target_site + 1 - aligned_start).next_multiple_of(4096);
                    if libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) == 0 {
                        let target_mut = std::slice::from_raw_parts_mut(target_site as *mut u8, 1);
                        target_mut[0] = 0x90; // nop out assertion int3 to execute error recovery / clean return
                        libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_EXEC);
                        tracing::info!(target_site = format_args!("{:#x}", target_site), "patched developer assert int3 -> nop to allow error recovery");
                    }
                }
            }
        }
    }
}

unsafe fn patch_dependency_assert_trap(base: usize, info: &ImageInfo) {
    let target_rva = 0x1adcd1e;
    let target_site = base + target_rva;
    if target_rva >= info.size_of_image as usize {
        return;
    }
    let slice = unsafe { std::slice::from_raw_parts(target_site as *const u8, 1) };
    if slice[0] != 0xcc {
        return;
    }

    #[cfg(unix)]
    unsafe {
        let aligned_start = target_site & !4095;
        let aligned_len = (target_site + 1 - aligned_start).next_multiple_of(4096);
        if libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) == 0 {
            let target_mut = std::slice::from_raw_parts_mut(target_site as *mut u8, 1);
            target_mut[0] = 0x90; // nop out int3 after vsnprintf assertion
            libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_EXEC);
            tracing::info!(target_site = format_args!("{:#x}", target_site), "patched dependency assert int3 -> nop");
        }
    }
}

unsafe fn patch_shader_missing_trap(base: usize, info: &ImageInfo) {
    let target_rva = 0x5c382b3;
    let target_site = base + target_rva;
    if target_rva >= info.size_of_image as usize {
        return;
    }
    let slice = unsafe { std::slice::from_raw_parts(target_site as *const u8, 1) };
    if slice[0] != 0xcc {
        return;
    }

    #[cfg(unix)]
    unsafe {
        let aligned_start = target_site & !4095;
        let aligned_len = (target_site + 1 - aligned_start).next_multiple_of(4096);
        if libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) == 0 {
            let target_mut = std::slice::from_raw_parts_mut(target_site as *mut u8, 1);
            target_mut[0] = 0x90; // nop out int3 in shader loader fallback path
            libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_EXEC);
            tracing::info!(target_site = format_args!("{:#x}", target_site), "patched shader missing assert int3 -> nop");
        }
    }
}

unsafe fn patch_shader_im_null_guard(base: usize, info: &ImageInfo) {
    let target_rva = 0x3750bd4;
    let target_site = base + target_rva;
    if target_rva + 7 >= info.size_of_image as usize {
        return;
    }
    let slice = unsafe { std::slice::from_raw_parts(target_site as *const u8, 7) };
    if slice != [0x0f, 0xb7, 0xae, 0xf8, 0x0c, 0x00, 0x00] {
        return;
    }

    let thunk_mem = match alloc_near(base, info.size_of_image as usize, 4096) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(error = %e, "failed to allocate thunk page for shader im null guard");
            return;
        }
    };
    let thunk_va = thunk_mem as usize;

    let mut thunk = Vec::with_capacity(32);
    thunk.extend_from_slice(&[0x48, 0x85, 0xf6]); // 0..3: test rsi, rsi
    thunk.extend_from_slice(&[0x74, 12]);         // 3..5: jz .Lskip (offset 17)
    thunk.extend_from_slice(&[0x0f, 0xb7, 0xae, 0xf8, 0x0c, 0x00, 0x00]); // 5..12: movzx ebp, word ptr [rsi + 0xcf8]
    let return_site = target_site + 7;
    let next_ip = thunk_va + 12 + 5;
    let disp = (return_site as i64 - next_ip as i64) as i32;
    thunk.push(0xe9);
    thunk.extend_from_slice(&disp.to_le_bytes()); // 12..17: jmp return_site
    thunk.extend_from_slice(&[0x31, 0xed]);       // 17..19: xor ebp, ebp
    thunk.extend_from_slice(&[0x31, 0xdb]);       // 19..21: xor ebx, ebx
    let skip_site = base + 0x3750c29;
    let next_ip2 = thunk_va + 21 + 5;
    let disp2 = (skip_site as i64 - next_ip2 as i64) as i32;
    thunk.push(0xe9);
    thunk.extend_from_slice(&disp2.to_le_bytes()); // 21..26: jmp skip_site

    #[cfg(unix)]
    unsafe {
        std::ptr::copy_nonoverlapping(thunk.as_ptr(), thunk_mem, thunk.len());
        libc::mprotect(thunk_mem as *mut libc::c_void, 4096, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC);
        let aligned_start = target_site & !4095;
        let aligned_len = (target_site + 7 - aligned_start).next_multiple_of(4096);
        if libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) == 0 {
            let target_mut = std::slice::from_raw_parts_mut(target_site as *mut u8, 7);
            let disp = (thunk_va as i64 - (target_site as i64 + 5)) as i32;
            target_mut[0] = 0xe9;
            target_mut[1..5].copy_from_slice(&disp.to_le_bytes());
            target_mut[5..7].fill(0x90);
            libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_EXEC);
            tracing::info!(target_site = format_args!("{:#x}", target_site), thunk_va = format_args!("{:#x}", thunk_va), "patched shader im null guard trampoline");
        }
    }
}

unsafe fn patch_clzero(base: usize, info: &ImageInfo) {
    let target_rva = 0x4e8aa10;
    let target_site = base + target_rva;
    if target_rva + 64 >= info.size_of_image as usize {
        return;
    }
    let slice = unsafe { std::slice::from_raw_parts(target_site as *const u8, 8) };
    if slice != [0x48, 0x8d, 0x41, 0x40, 0x4c, 0x8d, 0x91, 0xc0] {
        return;
    }

    const REPLACEMENT: &[u8] = &[
        0x57,                         // push rdi
        0x49, 0x89, 0xc8,             // mov r8, rcx
        0x48, 0x8d, 0x79, 0x40,       // lea rdi, [rcx + 0x40]
        0x31, 0xc0,                   // xor eax, eax
        0xb9, 0x80, 0x0e, 0x00, 0x00, // mov ecx, 0xe80
        0xf3, 0x48, 0xab,             // rep stosq
        0x5f,                         // pop rdi
        0xc5, 0xf8, 0x57, 0xc0,       // vxorps xmm0, xmm0, xmm0
        0x48, 0xb8, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, // movabs rax, 0xffffffffff
        0xc4, 0xc1, 0x7c, 0x29, 0x80, 0x40, 0xda, 0x00, 0x00,       // vmovaps ymmword ptr [r8 + 0xda40], ymm0
        0xc4, 0xc1, 0x7c, 0x29, 0x80, 0xc0, 0xda, 0x00, 0x00,       // vmovaps ymmword ptr [r8 + 0xdac0], ymm0
        0x0f, 0xae, 0xf8,             // sfence
        0x49, 0x89, 0x40, 0x20,       // mov qword ptr [r8 + 0x20], rax
        0xc5, 0xf8, 0x77,             // vzeroupper
        0xc3                          // ret
    ];

    #[cfg(unix)]
    unsafe {
        let aligned_start = target_site & !4095;
        let aligned_len = (target_site + REPLACEMENT.len() - aligned_start).next_multiple_of(4096);
        if libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) == 0 {
            let target_mut = std::slice::from_raw_parts_mut(target_site as *mut u8, REPLACEMENT.len());
            target_mut.copy_from_slice(REPLACEMENT);
            libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_EXEC);
            tracing::info!(target_site = format_args!("{:#x}", target_site), "patched clzero memory-zero routine for Apple Silicon / Rosetta 2");
        }
    }
}

unsafe fn patch_shader_lookup_dummy(base: usize, info: &ImageInfo) {
    let target_rva = 0x1adcd62;
    let target_site = base + target_rva;
    if target_rva + 15 >= info.size_of_image as usize {
        return;
    }
    let slice = unsafe { std::slice::from_raw_parts(target_site as *const u8, 15) };
    if slice != [0x48, 0x89, 0xf0, 0x48, 0x81, 0xc4, 0x38, 0x01, 0x00, 0x00, 0x5b, 0x5d, 0x5f, 0x5e, 0xc3] {
        return;
    }

    // Allocate 64KB dummy shader buffer
    let dummy_mem = match alloc_near(base, info.size_of_image as usize, 0x10000) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(error = %e, "failed to allocate dummy shader buffer");
            return;
        }
    };
    let dummy_va = dummy_mem as usize;
    unsafe {
        std::ptr::write_bytes(dummy_mem, 0, 0x10000);
        let sub_ptr = dummy_va + 0x3000;
        let sub_slice = std::slice::from_raw_parts_mut(dummy_mem.add(0x3000) as *mut usize, (0x10000 - 0x3000) / 8);
        sub_slice.fill(sub_ptr);

        // Keep 0x2000..0x3000 completely zeroed as an empty array/collection header (count = 0)
        let empty_list_ptr = dummy_va + 0x2000;

        // Point technique, pass and parameter pointers to empty list (count = 0)
        *(dummy_mem.add(0xc68) as *mut usize) = empty_list_ptr;
        *(dummy_mem.add(0xc70) as *mut usize) = empty_list_ptr;
        *(dummy_mem.add(0xc78) as *mut usize) = empty_list_ptr;
        *(dummy_mem.add(0xc80) as *mut usize) = empty_list_ptr;
        *(dummy_mem.add(0xc88) as *mut usize) = empty_list_ptr;
        *(dummy_mem.add(0xcf8) as *mut u16) = 0;

        // Point vtable pointers to ret instruction
        let ret_ptr = target_site + 14;
        for i in 0..64 {
            *(dummy_mem.add(i * 8) as *mut usize) = ret_ptr;
        }
    }

    // Allocate thunk for epilogue hook
    let thunk_mem = match alloc_near(base, info.size_of_image as usize, 4096) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(error = %e, "failed to allocate thunk page for shader lookup hook");
            return;
        }
    };
    let thunk_va = thunk_mem as usize;

    let mut thunk = Vec::with_capacity(32);
    thunk.extend_from_slice(&[0x48, 0x89, 0xf0]);                         // mov rax, rsi
    thunk.extend_from_slice(&[0x48, 0x81, 0xc4, 0x38, 0x01, 0x00, 0x00]); // add rsp, 0x138
    thunk.extend_from_slice(&[0x5b]);                                     // pop rbx
    thunk.extend_from_slice(&[0x5d]);                                     // pop rbp
    thunk.extend_from_slice(&[0x5f]);                                     // pop rdi
    thunk.extend_from_slice(&[0x5e]);                                     // pop rsi
    thunk.extend_from_slice(&[0x48, 0x85, 0xc0]);                         // test rax, rax
    thunk.extend_from_slice(&[0x75, 10]);                                 // jnz .Ldone (+10)
    thunk.extend_from_slice(&[0x48, 0xb8]);                               // movabs rax, dummy_va
    thunk.extend_from_slice(&dummy_va.to_le_bytes());
    thunk.extend_from_slice(&[0xc3]);                                     // ret

    #[cfg(unix)]
    unsafe {
        std::ptr::copy_nonoverlapping(thunk.as_ptr(), thunk_mem, thunk.len());
        libc::mprotect(thunk_mem as *mut libc::c_void, 4096, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC);
        let aligned_start = target_site & !4095;
        let aligned_len = (target_site + 15 - aligned_start).next_multiple_of(4096);
        if libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) == 0 {
            let target_mut = std::slice::from_raw_parts_mut(target_site as *mut u8, 15);
            let disp = (thunk_va as i64 - (target_site as i64 + 5)) as i32;
            target_mut[0] = 0xe9;
            target_mut[1..5].copy_from_slice(&disp.to_le_bytes());
            target_mut[5..15].fill(0x90);
            libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_EXEC);
            tracing::info!(target_site = format_args!("{:#x}", target_site), thunk_va = format_args!("{:#x}", thunk_va), dummy_va = format_args!("{:#x}", dummy_va), "patched shader lookup fallback to dummy shader object");
        }
    }
}

unsafe fn patch_array_search_null_guard(base: usize, info: &ImageInfo) {
    let target_rva = 0x5429d30;
    let target_site = base + target_rva;
    if target_rva + 11 >= info.size_of_image as usize {
        return;
    }
    let slice = unsafe { std::slice::from_raw_parts(target_site as *const u8, 11) };
    if slice != [0x48, 0x89, 0xc8, 0x0f, 0xb7, 0x09, 0x48, 0x85, 0xc9, 0x74, 0x2b] {
        return;
    }

    let exit_rva = 0x5429d66;
    let exit_site = base + exit_rva;
    let continue_site = target_site + 11;

    // Patch 0x5429d66 (the not-found return path) to return a pointer to a zeroed dummy entry
    let dummy_entry_mem = match alloc_near(base, info.size_of_image as usize, 4096) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(error = %e, "failed to allocate dummy entry buffer");
            return;
        }
    };
    let dummy_entry_va = dummy_entry_mem as usize;
    unsafe {
        std::ptr::write_bytes(dummy_entry_mem, 0, 4096);
    }

    let exit_thunk_mem = match alloc_near(base, info.size_of_image as usize, 4096) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(error = %e, "failed to allocate thunk page for array search dummy return");
            return;
        }
    };
    let exit_thunk_va = exit_thunk_mem as usize;

    let mut exit_thunk = Vec::with_capacity(16);
    exit_thunk.extend_from_slice(&[0x48, 0xb8]); // movabs rax, dummy_entry_va
    exit_thunk.extend_from_slice(&dummy_entry_va.to_le_bytes());
    exit_thunk.push(0xc3); // ret

    #[cfg(unix)]
    unsafe {
        std::ptr::copy_nonoverlapping(exit_thunk.as_ptr(), exit_thunk_mem, exit_thunk.len());
        libc::mprotect(exit_thunk_mem as *mut libc::c_void, 4096, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC);
        let aligned_start = exit_site & !4095;
        let aligned_len = (exit_site + 10 - aligned_start).next_multiple_of(4096);
        if libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) == 0 {
            let target_mut = std::slice::from_raw_parts_mut(exit_site as *mut u8, 10);
            let disp = (exit_thunk_va as i64 - (exit_site as i64 + 5)) as i32;
            target_mut[0] = 0xe9;
            target_mut[1..5].copy_from_slice(&disp.to_le_bytes());
            target_mut[5..10].fill(0x90);
            libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_EXEC);
            tracing::info!(exit_site = format_args!("{:#x}", exit_site), exit_thunk_va = format_args!("{:#x}", exit_thunk_va), dummy_entry_va = format_args!("{:#x}", dummy_entry_va), "patched array search not-found exit to return dummy entry");
        }
    }

    // Now allocate thunk for target_site (0x5429d30)
    let entry_thunk_mem = match alloc_near(base, info.size_of_image as usize, 4096) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(error = %e, "failed to allocate entry thunk for array search null guard");
            return;
        }
    };
    let entry_thunk_va = entry_thunk_mem as usize;

    let mut entry_thunk = Vec::with_capacity(40);
    entry_thunk.extend_from_slice(&[0x48, 0x85, 0xc9]); // test rcx, rcx
    entry_thunk.extend_from_slice(&[0x74, 0x17]);       // jz +23 -> offset 28 (exit jump)
    entry_thunk.extend_from_slice(&[0x48, 0x89, 0xc8]); // mov rax, rcx
    entry_thunk.extend_from_slice(&[0x0f, 0xb7, 0x09]); // movzx ecx, word ptr [rcx]
    entry_thunk.extend_from_slice(&[0x85, 0xc9]);       // test ecx, ecx
    entry_thunk.extend_from_slice(&[0x74, 0x0d]);       // jz +13 -> offset 28 (exit jump)
    entry_thunk.extend_from_slice(&[0x81, 0xf9, 0x00, 0x08, 0x00, 0x00]); // cmp ecx, 2048
    entry_thunk.extend_from_slice(&[0x77, 0x05]);       // ja +5 -> offset 28 (exit jump)

    let disp_continue = (continue_site as i64 - (entry_thunk_va as i64 + 23 + 5)) as i32;
    entry_thunk.push(0xe9);
    entry_thunk.extend_from_slice(&disp_continue.to_le_bytes());

    let disp_exit = (exit_site as i64 - (entry_thunk_va as i64 + 28 + 5)) as i32;
    entry_thunk.push(0xe9);
    entry_thunk.extend_from_slice(&disp_exit.to_le_bytes());

    #[cfg(unix)]
    unsafe {
        std::ptr::copy_nonoverlapping(entry_thunk.as_ptr(), entry_thunk_mem, entry_thunk.len());
        libc::mprotect(entry_thunk_mem as *mut libc::c_void, 4096, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC);

        let aligned_start = target_site & !4095;
        let aligned_len = (target_site + 11 - aligned_start).next_multiple_of(4096);
        if libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) == 0 {
            let target_mut = std::slice::from_raw_parts_mut(target_site as *mut u8, 11);
            let disp = (entry_thunk_va as i64 - (target_site as i64 + 5)) as i32;
            target_mut[0] = 0xe9;
            target_mut[1..5].copy_from_slice(&disp.to_le_bytes());
            target_mut[5..11].fill(0x90);
            libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_EXEC);
            tracing::info!(target_site = format_args!("{:#x}", target_site), entry_thunk_va = format_args!("{:#x}", entry_thunk_va), "patched array search entry guard to handle null rcx and zero count");
        }
    }
}

unsafe fn patch_shader_technique_null_guard(base: usize, info: &ImageInfo) {
    let target_rva = 0x54793f0;
    let target_site = base + target_rva;
    if target_rva + 8 >= info.size_of_image as usize {
        return;
    }
    let slice = unsafe { std::slice::from_raw_parts(target_site as *const u8, 8) };
    if slice != [0x56, 0x4c, 0x8b, 0x91, 0x68, 0x0c, 0x00, 0x00] {
        return;
    }

    let thunk_mem = match alloc_near(base, info.size_of_image as usize, 4096) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(error = %e, "failed to allocate thunk page for shader technique null guard");
            return;
        }
    };
    let thunk_va = thunk_mem as usize;

    let mut thunk = Vec::with_capacity(32);
    thunk.push(0x56); // push rsi
    thunk.extend_from_slice(&[0x4c, 0x8b, 0x91, 0x68, 0x0c, 0x00, 0x00]); // mov r10, qword ptr [rcx + 0xc68]
    thunk.extend_from_slice(&[0x4d, 0x85, 0xd2]); // test r10, r10
    thunk.extend_from_slice(&[0x74, 5]);          // jz .Lret (+5)
    let return_site = target_site + 8;
    let next_ip = thunk_va + 11 + 5;
    let disp = (return_site as i64 - next_ip as i64) as i32;
    thunk.push(0xe9);
    thunk.extend_from_slice(&disp.to_le_bytes()); // jmp return_site
    thunk.extend_from_slice(&[0x5e, 0xc3]);       // .Lret: pop rsi; ret

    #[cfg(unix)]
    unsafe {
        std::ptr::copy_nonoverlapping(thunk.as_ptr(), thunk_mem, thunk.len());
        libc::mprotect(thunk_mem as *mut libc::c_void, 4096, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC);
        let aligned_start = target_site & !4095;
        let aligned_len = (target_site + 8 - aligned_start).next_multiple_of(4096);
        if libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) == 0 {
            let target_mut = std::slice::from_raw_parts_mut(target_site as *mut u8, 8);
            let disp = (thunk_va as i64 - (target_site as i64 + 5)) as i32;
            target_mut[0] = 0xe9;
            target_mut[1..5].copy_from_slice(&disp.to_le_bytes());
            target_mut[5..8].fill(0x90);
            libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_EXEC);
            tracing::info!(target_site = format_args!("{:#x}", target_site), thunk_va = format_args!("{:#x}", thunk_va), "patched shader technique nil-r10 guard trampoline");
        }
    }
}

/// Protects the tracker release function at RVA 0x4da9f50.
/// 0x144da9f50 computes the tracker struct address from an object pointer:
/// (rdx - pool_base) / stride * 0x58 + tracker_base
/// If rdx < pool_base (e.g. dummy shader objects or external pointers), the subtraction
/// produces an underflow (e.g. 0xffffffffda0a4000), which divides to 0xffffed05,
/// indexing into an unmapped address (EXC_BAD_ACCESS code=2).
/// We hook 0x144da9f50 to verify rdx >= pool_base and stride != 0; otherwise returns 0.
unsafe fn patch_tracker_unref_guard(base: usize, info: &ImageInfo) {
    let target_rva = 0x4da9f50;
    let target_site = base + target_rva;
    if target_rva + 10 >= info.size_of_image as usize {
        return;
    }
    let slice = unsafe { std::slice::from_raw_parts(target_site as *const u8, 10) };
    if slice != [0x48, 0x89, 0xd0, 0x48, 0x2b, 0x05, 0x5e, 0x52, 0x83, 0x02] {
        return;
    }

    let thunk_mem = match alloc_near(base, info.size_of_image as usize, 4096) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(error = %e, "failed to allocate thunk page for tracker unref guard");
            return;
        }
    };
    let thunk_va = thunk_mem as usize;

    let pool_base_va = base + 0x75df1b8;
    let tracker_base_va = base + 0x75df1c0;
    let stride_va = base + 0x75df1cc;
    let target_ret_va = target_site + 0x30; // 0x144da9f80

    let mut thunk = Vec::with_capacity(128);
    // movabs rax, pool_base_va
    thunk.extend_from_slice(&[0x48, 0xb8]);
    thunk.extend_from_slice(&pool_base_va.to_le_bytes());
    // cmp rdx, qword ptr [rax]
    thunk.extend_from_slice(&[0x48, 0x3b, 0x10]);
    // jb .Linvalid
    let jb_off = thunk.len();
    thunk.extend_from_slice(&[0x72, 0x00]);

    // mov rax, rdx
    thunk.extend_from_slice(&[0x48, 0x89, 0xd0]);
    // movabs r8, pool_base_va
    thunk.extend_from_slice(&[0x49, 0xb8]);
    thunk.extend_from_slice(&pool_base_va.to_le_bytes());
    // sub rax, qword ptr [r8]
    thunk.extend_from_slice(&[0x49, 0x2b, 0x00]);
    // movabs r8, stride_va
    thunk.extend_from_slice(&[0x49, 0xb8]);
    thunk.extend_from_slice(&stride_va.to_le_bytes());
    // mov r8d, dword ptr [r8]
    thunk.extend_from_slice(&[0x45, 0x8b, 0x00]);
    // test r8d, r8d
    thunk.extend_from_slice(&[0x45, 0x85, 0xc0]);
    // jz .Linvalid
    let jz_off = thunk.len();
    thunk.extend_from_slice(&[0x74, 0x00]);

    // xor edx, edx
    thunk.extend_from_slice(&[0x31, 0xd2]);
    // div r8
    thunk.extend_from_slice(&[0x49, 0xf7, 0xf0]);
    // mov eax, eax
    thunk.extend_from_slice(&[0x89, 0xc0]);
    // imul rdx, rax, 0x58
    thunk.extend_from_slice(&[0x48, 0x6b, 0xd0, 0x58]);
    // movabs rax, tracker_base_va
    thunk.extend_from_slice(&[0x48, 0xb8]);
    thunk.extend_from_slice(&tracker_base_va.to_le_bytes());
    // add rdx, qword ptr [rax]
    thunk.extend_from_slice(&[0x48, 0x03, 0x10]);

    // jmp target_ret_va (0x144da9f80)
    let jmp_off = thunk.len();
    let next_ip = thunk_va + jmp_off + 5;
    let disp = (target_ret_va as i64 - next_ip as i64) as i32;
    thunk.push(0xe9);
    thunk.extend_from_slice(&disp.to_le_bytes());

    let invalid_off = thunk.len();
    thunk[jb_off + 1] = (invalid_off - (jb_off + 2)) as u8;
    thunk[jz_off + 1] = (invalid_off - (jz_off + 2)) as u8;

    // .Linvalid:
    // xor eax, eax
    thunk.extend_from_slice(&[0x31, 0xc0]);
    // ret
    thunk.push(0xc3);

    #[cfg(unix)]
    unsafe {
        std::ptr::copy_nonoverlapping(thunk.as_ptr(), thunk_mem, thunk.len());
        libc::mprotect(thunk_mem as *mut libc::c_void, 4096, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC);
        let aligned_start = target_site & !4095;
        let aligned_len = (target_site + 10 - aligned_start).next_multiple_of(4096);
        if libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) == 0 {
            let target_mut = std::slice::from_raw_parts_mut(target_site as *mut u8, 10);
            let disp = (thunk_va as i64 - (target_site as i64 + 5)) as i32;
            target_mut[0] = 0xe9;
            target_mut[1..5].copy_from_slice(&disp.to_le_bytes());
            target_mut[5..10].fill(0x90);
            libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC);
            tracing::info!(target_site = format_args!("{:#x}", target_site), thunk_va = format_args!("{:#x}", thunk_va), "patched tracker unref guard trampoline");
        }
    }
}

/// Guards against nil-dereference at RVA 0x5a75f73: mov al, byte ptr [rax + 0xaf].
/// When dictionary lookup returns 0 (not found), returning false (0) instead of dereferencing [0xaf].
unsafe fn patch_dict_result_null_guard(base: usize, info: &ImageInfo) {
    let target_rva = 0x5a75f73;
    let target_site = base + target_rva;
    if target_rva + 6 >= info.size_of_image as usize {
        return;
    }
    let slice = unsafe { std::slice::from_raw_parts(target_site as *const u8, 6) };
    if slice != [0x8a, 0x80, 0xaf, 0x00, 0x00, 0x00] {
        return;
    }

    let thunk_mem = match alloc_near(base, info.size_of_image as usize, 4096) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(error = %e, "failed to allocate thunk page for dict result null guard");
            return;
        }
    };
    let thunk_va = thunk_mem as usize;

    let mut thunk = Vec::with_capacity(32);
    // 48 85 c0: test rax, rax
    thunk.extend_from_slice(&[0x48, 0x85, 0xc0]);
    // 74 08: jz +8 (.Lnil)
    thunk.extend_from_slice(&[0x74, 0x08]);
    // 8a 80 af 00 00 00: mov al, byte ptr [rax + 0xaf]
    thunk.extend_from_slice(&[0x8a, 0x80, 0xaf, 0x00, 0x00, 0x00]);
    // eb 02: jmp +2 (.Lret)
    thunk.extend_from_slice(&[0xeb, 0x02]);
    // .Lnil: 30 c0: xor al, al
    thunk.extend_from_slice(&[0x30, 0xc0]);

    // .Lret: jmp target_site + 6
    let return_site = target_site + 6;
    let next_ip = thunk_va + thunk.len() + 5;
    let disp = (return_site as i64 - next_ip as i64) as i32;
    thunk.push(0xe9);
    thunk.extend_from_slice(&disp.to_le_bytes());

    #[cfg(unix)]
    unsafe {
        std::ptr::copy_nonoverlapping(thunk.as_ptr(), thunk_mem, thunk.len());
        libc::mprotect(thunk_mem as *mut libc::c_void, 4096, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC);
        let aligned_start = target_site & !4095;
        let aligned_len = (target_site + 6 - aligned_start).next_multiple_of(4096);
        if libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) == 0 {
            let target_mut = std::slice::from_raw_parts_mut(target_site as *mut u8, 6);
            let disp = (thunk_va as i64 - (target_site as i64 + 5)) as i32;
            target_mut[0] = 0xe9;
            target_mut[1..5].copy_from_slice(&disp.to_le_bytes());
            target_mut[5] = 0x90;
            libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC);
            tracing::info!(target_site = format_args!("{:#x}", target_site), thunk_va = format_args!("{:#x}", thunk_va), "patched dict result null guard trampoline");
        }
    }
}

/// Neutralizes __security_init_cookie fastfail abort at RVA 0x5600588.
/// 0x145600588: mov ecx, 2; int 0x29 (b9 02 00 00 00 cd 29).
/// Under Rosetta 2, calling __security_init_cookie checks if the cookie was already initialized
/// or mismatched, triggering FAST_FAIL_FATAL_APP_EXIT via int 0x29 (EXC_I386_GPFLT).
/// NOPing out `b9 02 00 00 00 cd 29` (7 bytes) allows execution to proceed directly to the cookie init.
unsafe fn patch_security_init_fastfail(base: usize, info: &ImageInfo) {
    let target_rva = 0x5600588;
    let target_site = base + target_rva;
    if target_rva + 7 >= info.size_of_image as usize {
        return;
    }
    let slice = unsafe { std::slice::from_raw_parts(target_site as *const u8, 7) };
    if slice != [0xb9, 0x02, 0x00, 0x00, 0x00, 0xcd, 0x29] {
        return;
    }

    #[cfg(unix)]
    unsafe {
        let aligned_start = target_site & !4095;
        let aligned_len = (target_site + 7 - aligned_start).next_multiple_of(4096);
        if libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) == 0 {
            let target_mut = std::slice::from_raw_parts_mut(target_site as *mut u8, 7);
            target_mut.fill(0x90);
            libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_EXEC);
            tracing::info!(target_site = format_args!("{:#x}", target_site), "patched security_init fastfail (mov ecx, 2; int 0x29) to nops");
        }
    }
}

/// Neutralizes null pointer dereference in string scanner at RVA 0x4e4ccc9.
/// 0x144e4ccc9: cmp byte ptr [rcx], 0; je 0x144e4ccfa (80 39 00 74 2c).
/// When callers pass rcx == 0 (NULL string), accessing [rcx] triggers EXC_BAD_ACCESS (code=1, address=0x0).
/// This trampoline tests rcx first: if null or empty (*rcx == 0), branches to 0x144e4ccfa which returns NULL (0);
/// otherwise continues at 0x144e4ccce to perform the scan.
unsafe fn patch_string_scan_null_guard(base: usize, info: &ImageInfo) {
    let target_rva = 0x4e4ccc9;
    let target_site = base + target_rva;
    if target_rva + 5 >= info.size_of_image as usize {
        return;
    }
    let slice = unsafe { std::slice::from_raw_parts(target_site as *const u8, 5) };
    if slice != [0x80, 0x39, 0x00, 0x74, 0x2c] {
        return;
    }

    let thunk_mem = match alloc_near(base, info.size_of_image as usize, 4096) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(error = %e, "failed to allocate thunk page for string scan null guard");
            return;
        }
    };
    let thunk_va = thunk_mem as usize;

    let target_continue = target_site + 5; // 0x144e4ccce
    let target_empty = base + 0x4e4ccfa;   // 0x144e4ccfa

    let mut thunk = Vec::with_capacity(32);
    // 0x00: 48 85 c9: test rcx, rcx
    thunk.extend_from_slice(&[0x48, 0x85, 0xc9]);
    // 0x03: 74 0a: jz +0x0a (.Lempty at 0x0f)
    thunk.extend_from_slice(&[0x74, 0x0a]);
    // 0x05: 80 39 00: cmp byte ptr [rcx], 0
    thunk.extend_from_slice(&[0x80, 0x39, 0x00]);
    // 0x08: 74 05: jz +0x05 (.Lempty at 0x0f)
    thunk.extend_from_slice(&[0x74, 0x05]);

    // 0x0a: jmp target_continue (0x144e4ccce)
    let next_ip_cont = thunk_va + thunk.len() + 5;
    let disp_cont = (target_continue as i64 - next_ip_cont as i64) as i32;
    thunk.push(0xe9);
    thunk.extend_from_slice(&disp_cont.to_le_bytes());

    // 0x0f: .Lempty: jmp target_empty (0x144e4ccfa)
    let next_ip_empty = thunk_va + thunk.len() + 5;
    let disp_empty = (target_empty as i64 - next_ip_empty as i64) as i32;
    thunk.push(0xe9);
    thunk.extend_from_slice(&disp_empty.to_le_bytes());

    #[cfg(unix)]
    unsafe {
        std::ptr::copy_nonoverlapping(thunk.as_ptr(), thunk_mem, thunk.len());
        libc::mprotect(thunk_mem as *mut libc::c_void, 4096, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC);
        let aligned_start = target_site & !4095;
        let aligned_len = (target_site + 5 - aligned_start).next_multiple_of(4096);
        if libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) == 0 {
            let target_mut = std::slice::from_raw_parts_mut(target_site as *mut u8, 5);
            let disp = (thunk_va as i64 - (target_site as i64 + 5)) as i32;
            target_mut[0] = 0xe9;
            target_mut[1..5].copy_from_slice(&disp.to_le_bytes());
            libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_EXEC);
            tracing::info!(target_site = format_args!("{:#x}", target_site), thunk_va = format_args!("{:#x}", thunk_va), "patched string scan null guard trampoline");
        }
    }
}

/// Neutralizes null pointer dereference when setting subsystem state field at RVA 0x57f9a81.
/// 0x1457f9a81: mov [rax + 0xfc4], ecx (89 88 c4 0f 00 00).
/// When rax == 0 (subsystem manager uninitialized or disabled), accessing [rax + 0xfc4] triggers
/// EXC_BAD_ACCESS (code=1, address=0xfc4).
/// This trampoline checks rax: only performs the write if rax != 0, then proceeds to 0x1457f9a87.
unsafe fn patch_manager_field_null_guard(base: usize, info: &ImageInfo) {
    let target_rva = 0x57f9a81;
    let target_site = base + target_rva;
    if target_rva + 6 >= info.size_of_image as usize {
        return;
    }
    let slice = unsafe { std::slice::from_raw_parts(target_site as *const u8, 6) };
    if slice != [0x89, 0x88, 0xc4, 0x0f, 0x00, 0x00] {
        return;
    }

    let thunk_mem = match alloc_near(base, info.size_of_image as usize, 4096) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(error = %e, "failed to allocate thunk page for manager field null guard");
            return;
        }
    };
    let thunk_va = thunk_mem as usize;

    let target_continue = target_site + 6; // 0x1457f9a87

    let mut thunk = Vec::with_capacity(32);
    // 0x00: 48 85 c0: test rax, rax
    thunk.extend_from_slice(&[0x48, 0x85, 0xc0]);
    // 0x03: 74 06: jz +0x06 (.Lskip at 0x0b)
    thunk.extend_from_slice(&[0x74, 0x06]);
    // 0x05: 89 88 c4 0f 00 00: mov [rax + 0xfc4], ecx
    thunk.extend_from_slice(&[0x89, 0x88, 0xc4, 0x0f, 0x00, 0x00]);
    // 0x0b: .Lskip: jmp target_continue (0x1457f9a87)
    let next_ip = thunk_va + thunk.len() + 5;
    let disp = (target_continue as i64 - next_ip as i64) as i32;
    thunk.push(0xe9);
    thunk.extend_from_slice(&disp.to_le_bytes());

    #[cfg(unix)]
    unsafe {
        std::ptr::copy_nonoverlapping(thunk.as_ptr(), thunk_mem, thunk.len());
        libc::mprotect(thunk_mem as *mut libc::c_void, 4096, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC);
        let aligned_start = target_site & !4095;
        let aligned_len = (target_site + 6 - aligned_start).next_multiple_of(4096);
        if libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) == 0 {
            let target_mut = std::slice::from_raw_parts_mut(target_site as *mut u8, 6);
            let disp = (thunk_va as i64 - (target_site as i64 + 5)) as i32;
            target_mut[0] = 0xe9;
            target_mut[1..5].copy_from_slice(&disp.to_le_bytes());
            target_mut[5] = 0x90; // nop
            libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_EXEC);
            tracing::info!(target_site = format_args!("{:#x}", target_site), thunk_va = format_args!("{:#x}", thunk_va), "patched manager field null guard trampoline");
        }
    }
}

/// Neutralizes __security_check_cookie abort at RVA 0x55ea040.
/// 0x1455ea040: cmp rcx, [rip + 0x11f7ff1]; jne ...; ret
/// Under Rosetta 2 or fiber stack context switches, security cookie mismatches trigger
/// __report_securityfailure -> TerminateProcess(0xc0000409).
/// Patching 0x1455ea040 with `ret` (0xc3) makes all stack cookie checks succeed unconditionally.
unsafe fn patch_security_check_cookie(base: usize, info: &ImageInfo) {
    let target_rva = 0x55ea040;
    let target_site = base + target_rva;
    if target_rva + 8 >= info.size_of_image as usize {
        return;
    }
    let slice = unsafe { std::slice::from_raw_parts(target_site as *const u8, 7) };
    if slice != [0x48, 0x3b, 0x0d, 0xf1, 0x7f, 0x1f, 0x01] {
        return;
    }

    #[cfg(unix)]
    unsafe {
        let aligned_start = target_site & !4095;
        let aligned_len = (target_site + 1 - aligned_start).next_multiple_of(4096);
        if libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) == 0 {
            let target_mut = std::slice::from_raw_parts_mut(target_site as *mut u8, 1);
            target_mut[0] = 0xc3; // ret
            libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_EXEC);
            tracing::info!(target_site = format_args!("{:#x}", target_site), "patched __security_check_cookie to immediate ret");
        }
    }
}

/// Neutralizes CRT fatal exit stub at RVA 0x5600728.
/// 0x145600728: TerminateProcess(GetCurrentProcess(), 0xc0000409).
/// Replaced with `ret` (0xc3) so any unhandled CRT abort cleanly returns instead of terminating.
unsafe fn patch_abort_terminate_stub(base: usize, info: &ImageInfo) {
    let target_rva = 0x5600728;
    let target_site = base + target_rva;
    if target_rva >= info.size_of_image as usize {
        return;
    }
    #[cfg(unix)]
    unsafe {
        let aligned_start = target_site & !4095;
        let aligned_len = (target_site + 1 - aligned_start).next_multiple_of(4096);
        if libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) == 0 {
            let target_mut = std::slice::from_raw_parts_mut(target_site as *mut u8, 1);
            target_mut[0] = 0xc3; // ret
            libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_EXEC);
            tracing::info!(target_site = format_args!("{:#x}", target_site), "patched CRT abort terminate stub to ret");
        }
    }
}

/// Neutralizes null virtual method call at RVA 0x1d400f8.
/// 0x141d400f8: mov rcx, [rax + 0x180]; mov rax, [rcx]; call [rax + 0x18] (13 bytes: 48 8b 88 80 01 00 00 48 8b 01 ff 50 18).
/// When subsystem object or its vtable is uninitialized/null, calling [rax + 0x18] branches to 0x0
/// triggering EXC_BAD_ACCESS (code=1, address=0x0).
/// This trampoline validates each pointer: if null, sets rax = 0; otherwise performs the call safely.
unsafe fn patch_vcall_null_guard(base: usize, info: &ImageInfo) {
    let target_rva = 0x1d400f8;
    let target_site = base + target_rva;
    if target_rva + 13 >= info.size_of_image as usize {
        return;
    }
    let slice = unsafe { std::slice::from_raw_parts(target_site as *const u8, 13) };
    if slice != [0x48, 0x8b, 0x88, 0x80, 0x01, 0x00, 0x00, 0x48, 0x8b, 0x01, 0xff, 0x50, 0x18] {
        return;
    }

    let thunk_mem = match alloc_near(base, info.size_of_image as usize, 4096) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(error = %e, "failed to allocate thunk page for vcall null guard");
            return;
        }
    };
    let thunk_va = thunk_mem as usize;

    let target_continue = target_site + 13; // 0x141d40105

    let mut thunk = Vec::with_capacity(64);
    // 0x00: 48 85 c0: test rax, rax
    thunk.extend_from_slice(&[0x48, 0x85, 0xc0]);
    // 0x03: 74 21: jz +0x21 (.Lnil at 0x26)
    thunk.extend_from_slice(&[0x74, 0x21]);
    // 0x05: 48 8b 88 80 01 00 00: mov rcx, [rax + 0x180]
    thunk.extend_from_slice(&[0x48, 0x8b, 0x88, 0x80, 0x01, 0x00, 0x00]);
    // 0x0c: 48 85 c9: test rcx, rcx
    thunk.extend_from_slice(&[0x48, 0x85, 0xc9]);
    // 0x0f: 74 15: jz +0x15 (.Lnil at 0x26)
    thunk.extend_from_slice(&[0x74, 0x15]);
    // 0x11: 48 8b 01: mov rax, [rcx]
    thunk.extend_from_slice(&[0x48, 0x8b, 0x01]);
    // 0x14: 48 85 c0: test rax, rax
    thunk.extend_from_slice(&[0x48, 0x85, 0xc0]);
    // 0x17: 74 0d: jz +0x0d (.Lnil at 0x26)
    thunk.extend_from_slice(&[0x74, 0x0d]);
    // 0x19: 48 8b 50 18: mov rdx, [rax + 0x18]
    thunk.extend_from_slice(&[0x48, 0x8b, 0x50, 0x18]);
    // 0x1d: 48 85 d2: test rdx, rdx
    thunk.extend_from_slice(&[0x48, 0x85, 0xd2]);
    // 0x20: 74 04: jz +0x04 (.Lnil at 0x26)
    thunk.extend_from_slice(&[0x74, 0x04]);
    // 0x22: ff d2: call rdx
    thunk.extend_from_slice(&[0xff, 0xd2]);
    // 0x24: eb 02: jmp +0x02 (.Lret at 0x28)
    thunk.extend_from_slice(&[0xeb, 0x02]);
    // 0x26: 31 c0: xor eax, eax
    thunk.extend_from_slice(&[0x31, 0xc0]);

    // 0x28: .Lret: jmp target_continue (0x141d40105)
    let next_ip = thunk_va + thunk.len() + 5;
    let disp = (target_continue as i64 - next_ip as i64) as i32;
    thunk.push(0xe9);
    thunk.extend_from_slice(&disp.to_le_bytes());

    #[cfg(unix)]
    unsafe {
        std::ptr::copy_nonoverlapping(thunk.as_ptr(), thunk_mem, thunk.len());
        libc::mprotect(thunk_mem as *mut libc::c_void, 4096, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC);
        let aligned_start = target_site & !4095;
        let aligned_len = (target_site + 13 - aligned_start).next_multiple_of(4096);
        if libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) == 0 {
            let target_mut = std::slice::from_raw_parts_mut(target_site as *mut u8, 13);
            let disp = (thunk_va as i64 - (target_site as i64 + 5)) as i32;
            target_mut[0] = 0xe9;
            target_mut[1..5].copy_from_slice(&disp.to_le_bytes());
            target_mut[5..13].fill(0x90);
            libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_EXEC);
            tracing::info!(target_site = format_args!("{:#x}", target_site), thunk_va = format_args!("{:#x}", thunk_va), "patched vcall null guard trampoline");
        }
    }
}

unsafe fn patch_entry_hash_null_guard(base: usize, info: &ImageInfo) {
    let target_rva = 0xb5a5f4;
    let target_site = base + target_rva;
    if target_rva + 8 >= info.size_of_image as usize {
        return;
    }
    let slice = unsafe { std::slice::from_raw_parts(target_site as *const u8, 8) };
    if slice != [0x88, 0x54, 0x24, 0x2f, 0x4c, 0x8b, 0x70, 0x68] {
        return;
    }

    let thunk_mem = match alloc_near(base, info.size_of_image as usize, 4096) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(error = %e, "failed to allocate thunk page for entry hash null guard");
            return;
        }
    };
    let thunk_va = thunk_mem as usize;

    let mut thunk = Vec::with_capacity(32);
    thunk.extend_from_slice(&[0x88, 0x54, 0x24, 0x2f]); // mov [rsp + 0x2f], dl
    thunk.extend_from_slice(&[0x48, 0x85, 0xc0]);       // test rax, rax
    thunk.extend_from_slice(&[0x74, 0x06]);             // jz +6 -> offset 15 (xor r14d, r14d)
    thunk.extend_from_slice(&[0x4c, 0x8b, 0x70, 0x68]); // mov r14, [rax + 0x68]
    thunk.extend_from_slice(&[0xeb, 0x03]);             // jmp +3 -> offset 18 (jmp return_site)
    thunk.extend_from_slice(&[0x45, 0x31, 0xf6]);       // xor r14d, r14d

    let return_site = target_site + 8;
    let disp_return = (return_site as i64 - (thunk_va as i64 + 18 + 5)) as i32;
    thunk.push(0xe9);
    thunk.extend_from_slice(&disp_return.to_le_bytes());

    #[cfg(unix)]
    unsafe {
        std::ptr::copy_nonoverlapping(thunk.as_ptr(), thunk_mem, thunk.len());
        libc::mprotect(thunk_mem as *mut libc::c_void, 4096, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC);

        let aligned_start = target_site & !4095;
        let aligned_len = (target_site + 8 - aligned_start).next_multiple_of(4096);
        if libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) == 0 {
            let target_mut = std::slice::from_raw_parts_mut(target_site as *mut u8, 8);
            let disp = (thunk_va as i64 - (target_site as i64 + 5)) as i32;
            target_mut[0] = 0xe9;
            target_mut[1..5].copy_from_slice(&disp.to_le_bytes());
            target_mut[5..8].fill(0x90);
            libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_EXEC);
            tracing::info!(target_site = format_args!("{:#x}", target_site), thunk_va = format_args!("{:#x}", thunk_va), "patched entry hash null guard trampoline");
        }
    }
}

unsafe fn patch_entry_hash_second_null_guard(base: usize, info: &ImageInfo) {
    let target_rva = 0xb5acf5;
    let target_site = base + target_rva;
    if target_rva + 13 >= info.size_of_image as usize {
        return;
    }
    let slice = unsafe { std::slice::from_raw_parts(target_site as *const u8, 13) };
    if slice != [0x48, 0x8b, 0x50, 0x08, 0x48, 0x85, 0xd2, 0x0f, 0x84, 0x03, 0xf9, 0xff, 0xff] {
        return;
    }

    let thunk_mem = match alloc_near(base, info.size_of_image as usize, 4096) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(error = %e, "failed to allocate thunk page for entry hash second null guard");
            return;
        }
    };
    let thunk_va = thunk_mem as usize;

    let skip_site = base + 0xb5a605;
    let continue_site = target_site + 13;

    let mut thunk = Vec::with_capacity(32);
    thunk.extend_from_slice(&[0x48, 0x85, 0xc0]); // test rax, rax
    thunk.extend_from_slice(&[0x74, 0x0c]);       // jz +12 -> offset 17
    thunk.extend_from_slice(&[0x48, 0x8b, 0x50, 0x08]); // mov rdx, [rax + 8]
    thunk.extend_from_slice(&[0x48, 0x85, 0xd2]); // test rdx, rdx
    thunk.extend_from_slice(&[0x74, 0x03]);       // jz +3 -> offset 17
    thunk.extend_from_slice(&[0xeb, 0x06]);       // jmp +6 -> offset 22
    thunk.push(0x90);                             // nop

    let disp_skip = (skip_site as i64 - (thunk_va as i64 + 17 + 5)) as i32;
    thunk.push(0xe9);
    thunk.extend_from_slice(&disp_skip.to_le_bytes());

    let disp_continue = (continue_site as i64 - (thunk_va as i64 + 22 + 5)) as i32;
    thunk.push(0xe9);
    thunk.extend_from_slice(&disp_continue.to_le_bytes());

    #[cfg(unix)]
    unsafe {
        std::ptr::copy_nonoverlapping(thunk.as_ptr(), thunk_mem, thunk.len());
        libc::mprotect(thunk_mem as *mut libc::c_void, 4096, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC);

        let aligned_start = target_site & !4095;
        let aligned_len = (target_site + 13 - aligned_start).next_multiple_of(4096);
        if libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) == 0 {
            let target_mut = std::slice::from_raw_parts_mut(target_site as *mut u8, 13);
            let disp = (thunk_va as i64 - (target_site as i64 + 5)) as i32;
            target_mut[0] = 0xe9;
            target_mut[1..5].copy_from_slice(&disp.to_le_bytes());
            target_mut[5..13].fill(0x90);
            libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_EXEC);
            tracing::info!(target_site = format_args!("{:#x}", target_site), thunk_va = format_args!("{:#x}", thunk_va), "patched entry hash second null guard trampoline");
        }
    }
}

unsafe fn patch_title_hash_worker_null_guard(base: usize, info: &ImageInfo) {
    let target_rva = 0x2479795;
    let target_site = base + target_rva;
    if target_rva + 9 >= info.size_of_image as usize {
        return;
    }
    let slice = unsafe { std::slice::from_raw_parts(target_site as *const u8, 9) };
    if slice != [0x4c, 0x8b, 0x68, 0x68, 0x48, 0x85, 0xc9, 0x74, 0x1a] {
        return;
    }

    let thunk_mem = match alloc_near(base, info.size_of_image as usize, 4096) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(error = %e, "failed to allocate thunk page for title hash worker null guard");
            return;
        }
    };
    let thunk_va = thunk_mem as usize;

    let skip_site = base + 0x24797b8;
    let continue_site = target_site + 9;

    let mut thunk = Vec::with_capacity(32);
    thunk.extend_from_slice(&[0x48, 0x85, 0xc0]);       // 0..3: test rax, rax
    thunk.extend_from_slice(&[0x74, 0x0b]);             // 3..5: jz .Lnull (offset 16)
    thunk.extend_from_slice(&[0x4c, 0x8b, 0x68, 0x68]); // 5..9: mov r13, [rax + 0x68]
    thunk.extend_from_slice(&[0x48, 0x85, 0xc9]);       // 9..12: test rcx, rcx
    thunk.extend_from_slice(&[0x74, 0x05]);             // 12..14: jz .Lskip (offset 19)
    thunk.extend_from_slice(&[0xeb, 0x08]);             // 14..16: jmp continue (offset 24)
    thunk.extend_from_slice(&[0x45, 0x31, 0xed]);       // 16..19: xor r13d, r13d (.Lnull)

    let disp_skip = (skip_site as i64 - (thunk_va as i64 + 19 + 5)) as i32;
    thunk.push(0xe9);
    thunk.extend_from_slice(&disp_skip.to_le_bytes());

    let disp_continue = (continue_site as i64 - (thunk_va as i64 + 24 + 5)) as i32;
    thunk.push(0xe9);
    thunk.extend_from_slice(&disp_continue.to_le_bytes());

    #[cfg(unix)]
    unsafe {
        std::ptr::copy_nonoverlapping(thunk.as_ptr(), thunk_mem, thunk.len());
        libc::mprotect(thunk_mem as *mut libc::c_void, 4096, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC);

        let aligned_start = target_site & !4095;
        let aligned_len = (target_site + 9 - aligned_start).next_multiple_of(4096);
        if libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) == 0 {
            let target_mut = std::slice::from_raw_parts_mut(target_site as *mut u8, 9);
            let disp = (thunk_va as i64 - (target_site as i64 + 5)) as i32;
            target_mut[0] = 0xe9;
            target_mut[1..5].copy_from_slice(&disp.to_le_bytes());
            target_mut[5..9].fill(0x90);
            libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_EXEC);
            tracing::info!(target_site = format_args!("{:#x}", target_site), thunk_va = format_args!("{:#x}", thunk_va), "patched title hash worker null guard trampoline");
        }
    }
}

unsafe fn patch_resource_init_r14_null_guard(base: usize, info: &ImageInfo) {
    let target_rva = 0x86f13c;
    let target_site = base + target_rva;
    if target_rva + 19 >= info.size_of_image as usize {
        return;
    }
    let slice = unsafe { std::slice::from_raw_parts(target_site as *const u8, 19) };
    if slice != [0x4c, 0x8b, 0x77, 0x08, 0x49, 0x8b, 0x86, 0x80, 0x00, 0x00, 0x00, 0x48, 0x89, 0x46, 0x08, 0x49, 0x8b, 0x56, 0x08] {
        return;
    }

    // Allocate 64KB dummy buffer for r14 resource fields
    let dummy_mem = match alloc_near(base, info.size_of_image as usize, 0x10000) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(error = %e, "failed to allocate dummy resource buffer");
            return;
        }
    };
    let dummy_va = dummy_mem as usize;
    unsafe {
        std::ptr::write_bytes(dummy_mem, 0, 0x10000);
    }

    let thunk_mem = match alloc_near(base, info.size_of_image as usize, 4096) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(error = %e, "failed to allocate thunk page for resource init r14 null guard");
            return;
        }
    };
    let thunk_va = thunk_mem as usize;

    let continue_site = target_site + 19; // 0x14086f14f

    let mut thunk = Vec::with_capacity(48);
    thunk.extend_from_slice(&[0x4c, 0x8b, 0x77, 0x08]); // 0..4: mov r14, [rdi + 8]
    thunk.extend_from_slice(&[0x4d, 0x85, 0xf6]);       // 4..7: test r14, r14
    thunk.extend_from_slice(&[0x75, 0x0a]);             // 7..9: jnz .Lvalid (offset 19)
    thunk.extend_from_slice(&[0x49, 0xbe]);             // 9..11: movabs r14, dummy_va
    thunk.extend_from_slice(&dummy_va.to_le_bytes());   // 11..19
    // 19..26: .Lvalid: mov rax, [r14 + 0x80]
    thunk.extend_from_slice(&[0x49, 0x8b, 0x86, 0x80, 0x00, 0x00, 0x00]);
    // 26..30: mov [rsi + 8], rax
    thunk.extend_from_slice(&[0x48, 0x89, 0x46, 0x08]);
    // 30..34: mov rdx, [r14 + 8]
    thunk.extend_from_slice(&[0x49, 0x8b, 0x56, 0x08]);

    let disp_continue = (continue_site as i64 - (thunk_va as i64 + 34 + 5)) as i32;
    thunk.push(0xe9);
    thunk.extend_from_slice(&disp_continue.to_le_bytes()); // 34..39: jmp continue_site

    #[cfg(unix)]
    unsafe {
        std::ptr::copy_nonoverlapping(thunk.as_ptr(), thunk_mem, thunk.len());
        libc::mprotect(thunk_mem as *mut libc::c_void, 4096, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC);

        let aligned_start = target_site & !4095;
        let aligned_len = (target_site + 19 - aligned_start).next_multiple_of(4096);
        if libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) == 0 {
            let target_mut = std::slice::from_raw_parts_mut(target_site as *mut u8, 19);
            let disp = (thunk_va as i64 - (target_site as i64 + 5)) as i32;
            target_mut[0] = 0xe9;
            target_mut[1..5].copy_from_slice(&disp.to_le_bytes());
            target_mut[5..19].fill(0x90);
            libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_EXEC);
            tracing::info!(target_site = format_args!("{:#x}", target_site), thunk_va = format_args!("{:#x}", thunk_va), dummy_va = format_args!("{:#x}", dummy_va), "patched resource init r14 null guard with dummy resource buffer");
        }
    }
}

/// Guards virtual call at RVA 0x1d400f8.
/// 0x141d400f8: mov rcx, [rax + 0x180]; mov rax, [rcx]; call [rax + 0x18]
/// If rax == 0, rcx == 0, [rcx] == 0, or [rax + 0x18] == 0, sets rax = 0 and jumps to 0x141d40105.
unsafe fn patch_event_listener_null_guard(base: usize, info: &ImageInfo) {
    let target_rva = 0x1d400f8;
    let target_site = base + target_rva;
    if target_rva + 13 >= info.size_of_image as usize {
        return;
    }

    let thunk_mem = match alloc_near(base, info.size_of_image as usize, 4096) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(error = %e, "failed to allocate thunk page for event listener null guard");
            return;
        }
    };
    let thunk_va = thunk_mem as usize;
    let continue_site = target_site + 13; // 0x141d40105

    let mut thunk = Vec::with_capacity(64);
    // test rax, rax
    thunk.extend_from_slice(&[0x48, 0x85, 0xc0]);
    // jz .Lnull (offset 38)
    thunk.extend_from_slice(&[0x74, 0x21]);
    // mov rcx, [rax + 0x180]
    thunk.extend_from_slice(&[0x48, 0x8b, 0x88, 0x80, 0x01, 0x00, 0x00]);
    // test rcx, rcx
    thunk.extend_from_slice(&[0x48, 0x85, 0xc9]);
    // jz .Lnull
    thunk.extend_from_slice(&[0x74, 0x15]);
    // mov rax, [rcx]
    thunk.extend_from_slice(&[0x48, 0x8b, 0x01]);
    // test rax, rax
    thunk.extend_from_slice(&[0x48, 0x85, 0xc0]);
    // jz .Lnull
    thunk.extend_from_slice(&[0x74, 0x0d]);
    // mov rdx, [rax + 0x18]
    thunk.extend_from_slice(&[0x48, 0x8b, 0x50, 0x18]);
    // test rdx, rdx
    thunk.extend_from_slice(&[0x48, 0x85, 0xd2]);
    // jz .Lnull
    thunk.extend_from_slice(&[0x74, 0x04]);
    // call rdx
    thunk.extend_from_slice(&[0xff, 0xd2]);
    // jmp .Lret
    thunk.extend_from_slice(&[0xeb, 0x02]);
    // .Lnull: xor eax, eax
    thunk.extend_from_slice(&[0x31, 0xc0]);
    // .Lret: jmp continue_site
    let disp_continue = (continue_site as i64 - (thunk_va as i64 + thunk.len() as i64 + 5)) as i32;
    thunk.push(0xe9);
    thunk.extend_from_slice(&disp_continue.to_le_bytes());

    #[cfg(unix)]
    unsafe {
        std::ptr::copy_nonoverlapping(thunk.as_ptr(), thunk_mem, thunk.len());
        libc::mprotect(thunk_mem as *mut libc::c_void, 4096, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC);

        let aligned_start = target_site & !4095;
        let aligned_len = (target_site + 13 - aligned_start).next_multiple_of(4096);
        if libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) == 0 {
            let target_mut = std::slice::from_raw_parts_mut(target_site as *mut u8, 13);
            let disp = (thunk_va as i64 - (target_site as i64 + 5)) as i32;
            target_mut[0] = 0xe9;
            target_mut[1..5].copy_from_slice(&disp.to_le_bytes());
            target_mut[5..13].fill(0x90);
            libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_EXEC);
            tracing::info!(target_site = format_args!("{:#x}", target_site), thunk_va = format_args!("{:#x}", thunk_va), "patched event listener null guard at 0x141d400f8");
        }
    }
}

/// Hooks COM factory query at RVA 0x55dd794.
/// The function attempts to instantiate GUID {073b7dcb-1fcf-4030-94be-e3c9eb623428} and invoke vmethod 0x60.
/// On macOS, this Xbox Live COM service is not present, leaving out-ptr NULL.
/// Returning S_OK (0) allows the calling subsystem to proceed safely.
unsafe fn patch_com_factory_null_guard(base: usize, info: &ImageInfo) {
    let target_rva = 0x55dd794;
    let target_site = base + target_rva;
    if target_rva + 8 >= info.size_of_image as usize {
        return;
    }

    #[cfg(unix)]
    unsafe {
        let aligned_start = target_site & !4095;
        let aligned_len = (target_site + 8 - aligned_start).next_multiple_of(4096);
        if libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) == 0 {
            let target_mut = std::slice::from_raw_parts_mut(target_site as *mut u8, 8);
            target_mut[0] = 0x31; // xor eax, eax
            target_mut[1] = 0xc0;
            target_mut[2] = 0xc3; // ret
            target_mut[3..8].fill(0x90);
            libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_EXEC);
            tracing::info!(target_site = format_args!("{:#x}", target_site), "patched COM factory null guard at 0x1455dd794");
        }
    }
}

unsafe fn patch_xbl_initialize_stub(base: usize, info: &ImageInfo) {
    let target_rva = 0x55ea1b0;
    let target_site = base + target_rva;
    if target_rva + 8 >= info.size_of_image as usize {
        return;
    }

    #[cfg(unix)]
    unsafe {
        let aligned_start = target_site & !4095;
        let aligned_len = (target_site + 8 - aligned_start).next_multiple_of(4096);
        if libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) == 0 {
            let target_mut = std::slice::from_raw_parts_mut(target_site as *mut u8, 8);
            target_mut[0] = 0x31; // xor eax, eax
            target_mut[1] = 0xc0;
            target_mut[2] = 0xc3; // ret
            target_mut[3..8].fill(0x90);
            libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_EXEC);
            tracing::info!(target_site = format_args!("{:#x}", target_site), "patched XblInitialize stub (S_OK) at 0x1455ea1b0");
        }
    }
}

unsafe fn patch_dict_field_null_guard(base: usize, info: &ImageInfo) {
    let target_rva = 0x582b0a3;
    let target_site = base + target_rva;
    if target_rva + 10 >= info.size_of_image as usize {
        return;
    }

    let thunk_mem = match alloc_near(base, info.size_of_image as usize, 4096) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(error = %e, "failed to allocate thunk page for dict field null guard");
            return;
        }
    };
    let thunk_va = thunk_mem as usize;

    let mut thunk = Vec::with_capacity(32);
    // test rax, rax
    thunk.extend_from_slice(&[0x48, 0x85, 0xc0]);
    // jz .Lnull (+4 bytes)
    thunk.extend_from_slice(&[0x74, 0x04]);
    // mov rax, [rax + 0x38]
    thunk.extend_from_slice(&[0x48, 0x8b, 0x40, 0x38]);
    // .Lnull:
    // add rsp, 0x20
    thunk.extend_from_slice(&[0x48, 0x83, 0xc4, 0x20]);
    // pop rsi
    thunk.push(0x5e);
    // ret
    thunk.push(0xc3);

    #[cfg(unix)]
    unsafe {
        std::ptr::copy_nonoverlapping(thunk.as_ptr(), thunk_mem, thunk.len());
        libc::mprotect(thunk_mem as *mut libc::c_void, 4096, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC);

        let aligned_start = target_site & !4095;
        let aligned_len = (target_site + 10 - aligned_start).next_multiple_of(4096);
        if libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) == 0 {
            let target_mut = std::slice::from_raw_parts_mut(target_site as *mut u8, 10);
            let rel = (thunk_va as i64) - ((target_site + 5) as i64);
            target_mut[0] = 0xe9; // jmp rel32
            target_mut[1..5].copy_from_slice(&(rel as i32).to_le_bytes());
            target_mut[5..10].fill(0x90);
            libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_EXEC);
            tracing::info!(target_site = format_args!("{:#x}", target_site), thunk_va = format_args!("{:#x}", thunk_va), "patched dict field null guard at 0x14582b0a3");
        }
    }
}

unsafe fn patch_assert_epilogue_trap(base: usize, info: &ImageInfo) {
    let targets = [0x1ddf97f, 0x3bf4];
    for &target_rva in &targets {
        let target_site = base + target_rva;
        if target_rva >= info.size_of_image as usize {
            continue;
        }

        #[cfg(unix)]
        unsafe {
            let aligned_start = target_site & !4095;
            let aligned_len = 4096;
            if libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) == 0 {
                let target_mut = std::slice::from_raw_parts_mut(target_site as *mut u8, 1);
                if target_mut[0] == 0xcc {
                    target_mut[0] = 0x90; // nop
                    tracing::info!(target_site = format_args!("{:#x}", target_site), "patched assert epilogue trap int3 -> nop");
                }
                libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_EXEC);
            }
        }
    }
}

unsafe fn patch_component_equality_null_guard(base: usize, info: &ImageInfo) {
    let target_rva = 0x55c9050;
    let target_site = base + target_rva;
    if target_rva + 15 >= info.size_of_image as usize {
        return;
    }

    let thunk_mem = match alloc_near(base, info.size_of_image as usize, 4096) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(error = %e, "failed to allocate thunk page for component equality null guard");
            return;
        }
    };
    let thunk_va = thunk_mem as usize;

    let mut thunk = Vec::with_capacity(32);
    // test rcx, rcx
    thunk.extend_from_slice(&[0x48, 0x85, 0xc9]);
    // jz .Lfalse
    let jz1_idx = thunk.len();
    thunk.extend_from_slice(&[0x74, 0x00]);
    // mov rax, [rcx + 0x8]
    thunk.extend_from_slice(&[0x48, 0x8b, 0x41, 0x08]);
    // test rax, rax
    thunk.extend_from_slice(&[0x48, 0x85, 0xc0]);
    // jz .Lfalse
    let jz2_idx = thunk.len();
    thunk.extend_from_slice(&[0x74, 0x00]);
    // movzwl 0x10(%rax), %eax
    thunk.extend_from_slice(&[0x0f, 0xb7, 0x40, 0x10]);
    // cmpl %eax, 0x20(%rcx)
    thunk.extend_from_slice(&[0x39, 0x41, 0x20]);
    // sete %al
    thunk.extend_from_slice(&[0x0f, 0x94, 0xc0]);
    // ret
    thunk.push(0xc3);
    // .Lfalse:
    let lfalse_idx = thunk.len();
    thunk[jz1_idx + 1] = (lfalse_idx - (jz1_idx + 2)) as u8;
    thunk[jz2_idx + 1] = (lfalse_idx - (jz2_idx + 2)) as u8;
    // xor eax, eax; ret
    thunk.extend_from_slice(&[0x31, 0xc0, 0xc3]);

    #[cfg(unix)]
    unsafe {
        std::ptr::copy_nonoverlapping(thunk.as_ptr(), thunk_mem, thunk.len());
        libc::mprotect(thunk_mem as *mut libc::c_void, 4096, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC);

        let aligned_start = target_site & !4095;
        let aligned_len = (target_site + 15 - aligned_start).next_multiple_of(4096);
        if libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) == 0 {
            let target_mut = std::slice::from_raw_parts_mut(target_site as *mut u8, 15);
            let rel = (thunk_va as i64) - ((target_site + 5) as i64);
            target_mut[0] = 0xe9; // jmp rel32
            target_mut[1..5].copy_from_slice(&(rel as i32).to_le_bytes());
            target_mut[5..15].fill(0x90);
            libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_EXEC);
            tracing::info!(target_site = format_args!("{:#x}", target_site), thunk_va = format_args!("{:#x}", thunk_va), "patched component equality null guard at 0x1455c9050");
        }
    }
}

unsafe fn patch_anim_table_lookup_null_guard(base: usize, info: &ImageInfo) {
    let target_rva = 0x58a8ad7;
    let target_site = base + target_rva;
    if target_rva + 7 >= info.size_of_image as usize {
        return;
    }
    let continue_site = target_site + 7; // 0x1458a8ade

    let thunk_mem = match alloc_near(base, info.size_of_image as usize, 4096) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(error = %e, "failed to allocate thunk page for anim table lookup null guard");
            return;
        }
    };
    let thunk_va = thunk_mem as usize;

    let global_va = target_site + 7 + 0x3f935f2; // 0x14983c0d0

    let mut thunk = Vec::with_capacity(48);
    // mov rcx, [rip + disp32] (loads from global_va)
    let disp_global = (global_va as i64 - (thunk_va as i64 + 7)) as i32;
    thunk.extend_from_slice(&[0x48, 0x8b, 0x0d]);
    thunk.extend_from_slice(&disp_global.to_le_bytes());
    // test rcx, rcx
    thunk.extend_from_slice(&[0x48, 0x85, 0xc9]);
    // jz .Lnull
    let jz_null_idx = thunk.len();
    thunk.extend_from_slice(&[0x74, 0x00]);
    // shll $4, %edx
    thunk.extend_from_slice(&[0xc1, 0xe2, 0x04]);
    // jmp continue_site
    let disp_cont = (continue_site as i64 - (thunk_va as i64 + thunk.len() as i64 + 5)) as i32;
    thunk.push(0xe9);
    thunk.extend_from_slice(&disp_cont.to_le_bytes());
    // .Lnull:
    let lnull_idx = thunk.len();
    thunk[jz_null_idx + 1] = (lnull_idx - (jz_null_idx + 2)) as u8;
    // xor eax, eax
    thunk.extend_from_slice(&[0x31, 0xc0]);
    // add rsp, 0x20
    thunk.extend_from_slice(&[0x48, 0x83, 0xc4, 0x20]);
    // pop rbx
    thunk.push(0x5b);
    // pop rdi
    thunk.push(0x5f);
    // pop rsi
    thunk.push(0x5e);
    // ret
    thunk.push(0xc3);

    #[cfg(unix)]
    unsafe {
        std::ptr::copy_nonoverlapping(thunk.as_ptr(), thunk_mem, thunk.len());
        libc::mprotect(thunk_mem as *mut libc::c_void, 4096, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC);

        let aligned_start = target_site & !4095;
        let aligned_len = (target_site + 7 - aligned_start).next_multiple_of(4096);
        if libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) == 0 {
            let target_mut = std::slice::from_raw_parts_mut(target_site as *mut u8, 7);
            let rel = (thunk_va as i64) - ((target_site + 5) as i64);
            target_mut[0] = 0xe9; // jmp rel32
            target_mut[1..5].copy_from_slice(&(rel as i32).to_le_bytes());
            target_mut[5..7].fill(0x90);
            libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_EXEC);
            tracing::info!(target_site = format_args!("{:#x}", target_site), thunk_va = format_args!("{:#x}", thunk_va), "patched anim table lookup null guard at 0x1458a8ad7");
        }
    }
}

unsafe fn patch_tunables_provider_null_guard(base: usize, info: &ImageInfo) {
    let target_rva = 0x2bc2dd6;
    let target_site = base + target_rva;
    if target_rva + 6 >= info.size_of_image as usize {
        return;
    }
    let slice = unsafe { std::slice::from_raw_parts(target_site as *const u8, 6) };
    if slice != [0x48, 0x89, 0xc1, 0x48, 0x89, 0xc6] {
        return;
    }

    let thunk_mem = match alloc_near(base, info.size_of_image as usize, 4096) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(error = %e, "failed to allocate thunk page for tunables provider null guard");
            return;
        }
    };
    let thunk_va = thunk_mem as usize;

    let mut thunk = Vec::with_capacity(128);
    // test rax, rax
    thunk.extend_from_slice(&[0x48, 0x85, 0xc0]);
    // jnz .Lvalid (+7 bytes: lea rax, [rip + disp32])
    thunk.extend_from_slice(&[0x75, 0x07]);
    // lea rax, [rip + disp32] (points to dummy zero buffer at offset 64)
    let dummy_offset = 64i32;
    let next_ip_lea = (thunk.len() + 7) as i32;
    let disp_dummy = dummy_offset - next_ip_lea;
    thunk.extend_from_slice(&[0x48, 0x8d, 0x05]);
    thunk.extend_from_slice(&disp_dummy.to_le_bytes());
    // .Lvalid:
    // mov rcx, rax
    thunk.extend_from_slice(&[0x48, 0x89, 0xc1]);
    // mov rsi, rax
    thunk.extend_from_slice(&[0x48, 0x89, 0xc6]);
    // jmp target_site + 6
    let return_site = target_site + 6;
    let next_ip = thunk_va + thunk.len() + 5;
    let disp_return = (return_site as i64 - next_ip as i64) as i32;
    thunk.push(0xe9);
    thunk.extend_from_slice(&disp_return.to_le_bytes());

    #[cfg(unix)]
    unsafe {
        std::ptr::write_bytes(thunk_mem, 0, 4096);
        std::ptr::copy_nonoverlapping(thunk.as_ptr(), thunk_mem, thunk.len());
        libc::mprotect(thunk_mem as *mut libc::c_void, 4096, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC);

        let aligned_start = target_site & !4095;
        let aligned_len = (target_site + 6 - aligned_start).next_multiple_of(4096);
        if libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) == 0 {
            let target_mut = std::slice::from_raw_parts_mut(target_site as *mut u8, 6);
            let rel = (thunk_va as i64) - ((target_site + 5) as i64);
            target_mut[0] = 0xe9;
            target_mut[1..5].copy_from_slice(&(rel as i32).to_le_bytes());
            target_mut[5] = 0x90;
            libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_EXEC);
            tracing::info!(target_site = format_args!("{:#x}", target_site), thunk_va = format_args!("{:#x}", thunk_va), "patched tunables provider null guard at 0x142bc2dd6");
        }
    }
}

unsafe fn patch_vector_scale_null_guard(base: usize, info: &ImageInfo) {
    let target_rva = 0x5ec3ed0;
    let target_site = base + target_rva;
    if target_rva + 13 >= info.size_of_image as usize {
        return;
    }
    let slice = unsafe { std::slice::from_raw_parts(target_site as *const u8, 13) };
    if slice != [0xc5, 0xfa, 0x10, 0x01, 0xc4, 0xe2, 0x79, 0x18, 0x15, 0xaf, 0x6f, 0x29, 0x00] {
        return;
    }

    let thunk_mem = match alloc_near(base, info.size_of_image as usize, 4096) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(error = %e, "failed to allocate thunk page for vector scale null guard");
            return;
        }
    };
    let thunk_va = thunk_mem as usize;

    let mut thunk = Vec::with_capacity(64);
    // test rcx, rcx
    thunk.extend_from_slice(&[0x48, 0x85, 0xc9]);
    // jz .Lret
    let jz_idx = thunk.len();
    thunk.extend_from_slice(&[0x74, 0x00]); // placeholder

    // vmovss xmm0, [rcx]
    thunk.extend_from_slice(&[0xc5, 0xfa, 0x10, 0x01]);

    // vbroadcastss xmm2, [global_addr]
    let global_addr = target_site + 13 + 0x296faf;
    let next_ip_vbc = thunk_va + thunk.len() + 9;
    let disp_global = (global_addr as i64 - next_ip_vbc as i64) as i32;
    thunk.extend_from_slice(&[0xc4, 0xe2, 0x79, 0x18, 0x15]);
    thunk.extend_from_slice(&disp_global.to_le_bytes());

    // jmp target_site + 13
    let return_site = target_site + 13;
    let next_ip = thunk_va + thunk.len() + 5;
    let disp_return = (return_site as i64 - next_ip as i64) as i32;
    thunk.push(0xe9);
    thunk.extend_from_slice(&disp_return.to_le_bytes());

    // .Lret:
    let lret_off = thunk.len();
    thunk[jz_idx + 1] = (lret_off - (jz_idx + 2)) as u8;
    thunk.push(0xc3); // ret

    #[cfg(unix)]
    unsafe {
        std::ptr::copy_nonoverlapping(thunk.as_ptr(), thunk_mem, thunk.len());
        libc::mprotect(thunk_mem as *mut libc::c_void, 4096, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC);

        let aligned_start = target_site & !4095;
        let aligned_len = (target_site + 13 - aligned_start).next_multiple_of(4096);
        if libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) == 0 {
            let target_mut = std::slice::from_raw_parts_mut(target_site as *mut u8, 13);
            let rel = (thunk_va as i64) - ((target_site + 5) as i64);
            target_mut[0] = 0xe9;
            target_mut[1..5].copy_from_slice(&(rel as i32).to_le_bytes());
            target_mut[5..13].fill(0x90);
            libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_EXEC);
            tracing::info!(target_site = format_args!("{:#x}", target_site), thunk_va = format_args!("{:#x}", thunk_va), "patched vector scale null guard at 0x145ec3ed0");
        }
    }
}

unsafe fn patch_node_lookup_null_guard(base: usize, info: &ImageInfo) {
    let target_rva = 0x4e4f030;
    let target_site = base + target_rva;
    if target_rva + 9 >= info.size_of_image as usize {
        return;
    }
    let slice = unsafe { std::slice::from_raw_parts(target_site as *const u8, 9) };
    if slice != [0x56, 0x48, 0x83, 0xec, 0x20, 0x48, 0x8b, 0x41, 0x08] {
        return;
    }

    let thunk_mem = match alloc_near(base, info.size_of_image as usize, 4096) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(error = %e, "failed to allocate thunk page for node lookup null guard");
            return;
        }
    };
    let thunk_va = thunk_mem as usize;

    let mut thunk = Vec::with_capacity(64);
    // push rsi
    thunk.push(0x56);
    // sub rsp, 0x20
    thunk.extend_from_slice(&[0x48, 0x83, 0xec, 0x20]);
    // test rcx, rcx
    thunk.extend_from_slice(&[0x48, 0x85, 0xc9]);
    // jz .Lnull
    let jz_rcx_idx = thunk.len();
    thunk.extend_from_slice(&[0x74, 0x00]);
    // mov rax, [rcx + 8]
    thunk.extend_from_slice(&[0x48, 0x8b, 0x41, 0x08]);
    // test rax, rax
    thunk.extend_from_slice(&[0x48, 0x85, 0xc0]);
    // jz .Lnull
    let jz_rax_idx = thunk.len();
    thunk.extend_from_slice(&[0x74, 0x00]);

    // jmp target_site + 9
    let return_site = target_site + 9;
    let next_ip = thunk_va + thunk.len() + 5;
    let disp_return = (return_site as i64 - next_ip as i64) as i32;
    thunk.push(0xe9);
    thunk.extend_from_slice(&disp_return.to_le_bytes());

    // .Lnull:
    let lnull_off = thunk.len();
    thunk[jz_rcx_idx + 1] = (lnull_off - (jz_rcx_idx + 2)) as u8;
    thunk[jz_rax_idx + 1] = (lnull_off - (jz_rax_idx + 2)) as u8;
    // xor eax, eax
    thunk.extend_from_slice(&[0x31, 0xc0]);
    // add rsp, 0x20
    thunk.extend_from_slice(&[0x48, 0x83, 0xc4, 0x20]);
    // pop rsi
    thunk.push(0x5e);
    // ret
    thunk.push(0xc3);

    #[cfg(unix)]
    unsafe {
        std::ptr::copy_nonoverlapping(thunk.as_ptr(), thunk_mem, thunk.len());
        libc::mprotect(thunk_mem as *mut libc::c_void, 4096, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC);

        let aligned_start = target_site & !4095;
        let aligned_len = (target_site + 9 - aligned_start).next_multiple_of(4096);
        if libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) == 0 {
            let target_mut = std::slice::from_raw_parts_mut(target_site as *mut u8, 9);
            let rel = (thunk_va as i64) - ((target_site + 5) as i64);
            target_mut[0] = 0xe9;
            target_mut[1..5].copy_from_slice(&(rel as i32).to_le_bytes());
            target_mut[5..9].fill(0x90);
            libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_EXEC);
            tracing::info!(target_site = format_args!("{:#x}", target_site), thunk_va = format_args!("{:#x}", thunk_va), "patched node lookup null guard at 0x144e4f030");
        }
    }
}

unsafe fn patch_cmpl_assert_trap(base: usize, info: &ImageInfo) {
    let target_rva = 0x55aa5eb;
    let target_site = base + target_rva;
    if target_rva + 3 >= info.size_of_image as usize {
        return;
    }
    let slice = unsafe { std::slice::from_raw_parts(target_site as *const u8, 3) };
    if slice != [0xcc, 0xeb, 0xbe] {
        return;
    }
    #[cfg(unix)]
    unsafe {
        let aligned_start = target_site & !4095;
        let aligned_len = (target_site + 3 - aligned_start).next_multiple_of(4096);
        if libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) == 0 {
            let target_mut = std::slice::from_raw_parts_mut(target_site as *mut u8, 1);
            target_mut[0] = 0x90; // nop
            libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_EXEC);
            tracing::info!(target_site = format_args!("{:#x}", target_site), "patched developer assert int3 -> nop at 0x1455aa5eb");
        }
    }
}

unsafe fn patch_node_lookup_tailcall_null_guard(base: usize, info: &ImageInfo) {
    let target_rva = 0x55912e0;
    let target_site = base + target_rva;
    if target_rva + 21 >= info.size_of_image as usize {
        return;
    }
    let slice = unsafe { std::slice::from_raw_parts(target_site as *const u8, 21) };
    if slice != [
        0x48, 0x8b, 0x41, 0x08,
        0x44, 0x8b, 0x41, 0x20,
        0x48, 0x8b, 0x51, 0x18,
        0x48, 0x8b, 0x48, 0x08,
        0xe9, 0x6b, 0xdd, 0x8b, 0xff,
    ] {
        return;
    }

    let thunk_mem = match alloc_near(base, info.size_of_image as usize, 4096) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(error = %e, "failed to allocate thunk page for node lookup tailcall null guard");
            return;
        }
    };
    let thunk_va = thunk_mem as usize;

    let helper_site = base + 0x4e4f060;

    let mut thunk = Vec::with_capacity(64);
    // test rcx, rcx
    thunk.extend_from_slice(&[0x48, 0x85, 0xc9]);
    // jz .Lnull
    let jz_rcx_idx = thunk.len();
    thunk.extend_from_slice(&[0x74, 0x00]);
    // mov rax, [rcx + 8]
    thunk.extend_from_slice(&[0x48, 0x8b, 0x41, 0x08]);
    // test rax, rax
    thunk.extend_from_slice(&[0x48, 0x85, 0xc0]);
    // jz .Lnull
    let jz_rax_idx = thunk.len();
    thunk.extend_from_slice(&[0x74, 0x00]);
    // mov r8d, [rcx + 0x20]
    thunk.extend_from_slice(&[0x44, 0x8b, 0x41, 0x20]);
    // mov rdx, [rcx + 0x18]
    thunk.extend_from_slice(&[0x48, 0x8b, 0x51, 0x18]);
    // mov rcx, [rax + 8]
    thunk.extend_from_slice(&[0x48, 0x8b, 0x48, 0x08]);
    // jmp helper_site (0x144e4f060)
    let next_ip = thunk_va + thunk.len() + 5;
    let disp_helper = (helper_site as i64 - next_ip as i64) as i32;
    thunk.push(0xe9);
    thunk.extend_from_slice(&disp_helper.to_le_bytes());

    // .Lnull:
    let lnull_off = thunk.len();
    thunk[jz_rcx_idx + 1] = (lnull_off - (jz_rcx_idx + 2)) as u8;
    thunk[jz_rax_idx + 1] = (lnull_off - (jz_rax_idx + 2)) as u8;
    // xor eax, eax
    thunk.extend_from_slice(&[0x31, 0xc0]);
    // ret
    thunk.push(0xc3);

    #[cfg(unix)]
    unsafe {
        std::ptr::copy_nonoverlapping(thunk.as_ptr(), thunk_mem, thunk.len());
        libc::mprotect(thunk_mem as *mut libc::c_void, 4096, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC);

        let aligned_start = target_site & !4095;
        let aligned_len = (target_site + 21 - aligned_start).next_multiple_of(4096);
        if libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) == 0 {
            let target_mut = std::slice::from_raw_parts_mut(target_site as *mut u8, 21);
            let rel = (thunk_va as i64) - ((target_site + 5) as i64);
            target_mut[0] = 0xe9;
            target_mut[1..5].copy_from_slice(&(rel as i32).to_le_bytes());
            target_mut[5..21].fill(0x90);
            libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_EXEC);
            tracing::info!(target_site = format_args!("{:#x}", target_site), thunk_va = format_args!("{:#x}", thunk_va), "patched node lookup tailcall null guard at 0x1455912e0");
        }
    }
}

unsafe fn patch_zero_pointer_guard(base: usize, info: &ImageInfo) {
    let target_rva = 0x15dd8e8;
    let target_site = base + target_rva;
    if target_rva + 8 >= info.size_of_image as usize {
        return;
    }
    let slice = unsafe { std::slice::from_raw_parts(target_site as *const u8, 8) };
    if slice != [0x49, 0xc7, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc3] {
        return;
    }

    let thunk_mem = match alloc_near(base, info.size_of_image as usize, 4096) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(error = %e, "failed to allocate thunk page for zero pointer guard");
            return;
        }
    };
    let thunk_va = thunk_mem as usize;

    let mut thunk = Vec::with_capacity(32);
    // test r8, r8
    thunk.extend_from_slice(&[0x4d, 0x85, 0xc0]);
    // jz .Lret (+7 bytes)
    thunk.extend_from_slice(&[0x74, 0x07]);
    // mov qword ptr [r8], 0
    thunk.extend_from_slice(&[0x49, 0xc7, 0x00, 0x00, 0x00, 0x00, 0x00]);
    // .Lret:
    // ret
    thunk.push(0xc3);

    #[cfg(unix)]
    unsafe {
        std::ptr::copy_nonoverlapping(thunk.as_ptr(), thunk_mem, thunk.len());
        libc::mprotect(thunk_mem as *mut libc::c_void, 4096, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC);

        let aligned_start = target_site & !4095;
        let aligned_len = (target_site + 8 - aligned_start).next_multiple_of(4096);
        if libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) == 0 {
            let target_mut = std::slice::from_raw_parts_mut(target_site as *mut u8, 8);
            let rel = (thunk_va as i64) - ((target_site + 5) as i64);
            target_mut[0] = 0xe9;
            target_mut[1..5].copy_from_slice(&(rel as i32).to_le_bytes());
            target_mut[5..8].fill(0x90);
            libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_EXEC);
            tracing::info!(target_site = format_args!("{:#x}", target_site), thunk_va = format_args!("{:#x}", thunk_va), "patched zero pointer guard at 0x1415dd8e8");
        }
    }
}

unsafe fn patch_rdx_null_guard(base: usize, info: &ImageInfo) {
    let target_rva = 0x557c220;
    let target_site = base + target_rva;
    if target_rva + 7 >= info.size_of_image as usize {
        return;
    }
    let slice = unsafe { std::slice::from_raw_parts(target_site as *const u8, 7) };
    if slice != [0x56, 0x57, 0x53, 0x48, 0x83, 0xec, 0x20] {
        return;
    }

    let thunk_mem = match alloc_near(base, info.size_of_image as usize, 4096) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(error = %e, "failed to allocate thunk page for rdx null guard");
            return;
        }
    };
    let thunk_va = thunk_mem as usize;

    let mut thunk = Vec::with_capacity(64);
    // push rsi
    thunk.push(0x56);
    // push rdi
    thunk.push(0x57);
    // push rbx
    thunk.push(0x53);
    // sub rsp, 0x20
    thunk.extend_from_slice(&[0x48, 0x83, 0xec, 0x20]);
    // test rdx, rdx
    thunk.extend_from_slice(&[0x48, 0x85, 0xd2]);
    // jz .Lzero_rdx
    let jz_rdx_idx = thunk.len();
    thunk.extend_from_slice(&[0x74, 0x00]);
    // mov rsi, [rdx]
    thunk.extend_from_slice(&[0x48, 0x8b, 0x32]);
    // test rsi, rsi
    thunk.extend_from_slice(&[0x48, 0x85, 0xf6]);
    // jz .Lzero_rsi
    let jz_rsi_idx = thunk.len();
    thunk.extend_from_slice(&[0x74, 0x00]);

    // proceed: jmp target_site + 19
    let proceed_site = target_site + 19;
    let next_ip = thunk_va + thunk.len() + 5;
    let disp_proceed = (proceed_site as i64 - next_ip as i64) as i32;
    thunk.push(0xe9);
    thunk.extend_from_slice(&disp_proceed.to_le_bytes());

    // .Lzero_rdx:
    let lzero_rdx = thunk.len();
    thunk[jz_rdx_idx + 1] = (lzero_rdx - (jz_rdx_idx + 2)) as u8;
    // xor esi, esi
    thunk.extend_from_slice(&[0x31, 0xf6]);

    // .Lzero_rsi:
    let lzero_rsi = thunk.len();
    thunk[jz_rsi_idx + 1] = (lzero_rsi - (jz_rsi_idx + 2)) as u8;
    // jmp exit_site (base + 0x557c2d1)
    let exit_site = base + 0x557c2d1;
    let next_ip = thunk_va + thunk.len() + 5;
    let disp_exit = (exit_site as i64 - next_ip as i64) as i32;
    thunk.push(0xe9);
    thunk.extend_from_slice(&disp_exit.to_le_bytes());

    #[cfg(unix)]
    unsafe {
        std::ptr::copy_nonoverlapping(thunk.as_ptr(), thunk_mem, thunk.len());
        libc::mprotect(thunk_mem as *mut libc::c_void, 4096, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC);

        let aligned_start = target_site & !4095;
        let aligned_len = (target_site + 7 - aligned_start).next_multiple_of(4096);
        if libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) == 0 {
            let target_mut = std::slice::from_raw_parts_mut(target_site as *mut u8, 7);
            let rel = (thunk_va as i64) - ((target_site + 5) as i64);
            target_mut[0] = 0xe9;
            target_mut[1..5].copy_from_slice(&(rel as i32).to_le_bytes());
            target_mut[5..7].fill(0x90);
            libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_EXEC);
            tracing::info!(target_site = format_args!("{:#x}", target_site), thunk_va = format_args!("{:#x}", thunk_va), "patched rdx null guard at 0x14557c220");
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "win64" fn victory_alloc_fallback_heap(size: usize) -> *mut u8 {
    let alloc_size = std::cmp::max(size, 0x20_0000).next_multiple_of(4096);
    let p = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            alloc_size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_ANON | libc::MAP_PRIVATE,
            -1,
            0,
        )
    };
    if p != libc::MAP_FAILED {
        p as *mut u8
    } else {
        std::ptr::null_mut()
    }
}

unsafe fn patch_heap_alloc_fallback(base: usize, info: &ImageInfo) {
    let target_rva = 0x1a65f50;
    let target_site = base + target_rva;
    let patch_len = 12;
    if target_rva + patch_len >= info.size_of_image as usize {
        return;
    }
    // Expected function prologue:
    // 41 57: push r15
    // 41 56: push r14
    // 56:    push rsi
    // 57:    push rdi
    // 55:    push rbp
    // 53:    push rbx
    // 48 83 ec 28: sub rsp, 0x28
    let expected = [0x41, 0x57, 0x41, 0x56, 0x56, 0x57, 0x55, 0x53, 0x48, 0x83, 0xec, 0x28];
    let slice = unsafe { std::slice::from_raw_parts(target_site as *const u8, patch_len) };
    if slice != expected {
        return;
    }

    let thunk_mem = match alloc_near(base, info.size_of_image as usize, 4096) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(error = %e, "failed to allocate fallback heap memory for resource table");
            return;
        }
    };
    let thunk_va = thunk_mem as usize;
    let target_continue = target_site + patch_len;

    let mut thunk = Vec::with_capacity(64);
    // cmp rcx, 0x10000
    // jae .Lvalid_rcx (+0x10)
    // xor eax, eax
    // ret
    // .Lvalid_rcx:
    // push r15
    // push r14
    // push rsi
    // push rdi
    // push rbp
    // push rbx
    // sub rsp, 0x28
    // jmp target_continue
    thunk.extend_from_slice(&[
        0x48, 0x81, 0xf9, 0x00, 0x00, 0x01, 0x00, // cmp rcx, 0x10000
        0x73, 0x03,                               // jae +3 -> .Lvalid_rcx
        0x31, 0xc0,                               // xor eax, eax
        0xc3,                                     // ret
        // .Lvalid_rcx:
        0x41, 0x57,                               // push r15
        0x41, 0x56,                               // push r14
        0x56,                                     // push rsi
        0x57,                                     // push rdi
        0x55,                                     // push rbp
        0x53,                                     // push rbx
        0x48, 0x83, 0xec, 0x28,                   // sub rsp, 0x28
    ]);
    let next_ip = thunk_va + thunk.len() + 5;
    let disp_return = (target_continue as i64 - next_ip as i64) as i32;
    thunk.push(0xe9);
    thunk.extend_from_slice(&disp_return.to_le_bytes());

    #[cfg(unix)]
    unsafe {
        std::ptr::copy_nonoverlapping(thunk.as_ptr(), thunk_mem, thunk.len());
        libc::mprotect(thunk_mem as *mut libc::c_void, 4096, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC);

        let aligned_start = target_site & !4095;
        let aligned_len = (target_site + patch_len - aligned_start).next_multiple_of(4096);
        if libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) == 0 {
            let target_mut = std::slice::from_raw_parts_mut(target_site as *mut u8, patch_len);
            let rel = (thunk_va as i64) - ((target_site + 5) as i64);
            target_mut[0] = 0xe9;
            target_mut[1..5].copy_from_slice(&(rel as i32).to_le_bytes());
            target_mut[5..patch_len].fill(0x90);
            libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_EXEC);
            tracing::info!(target_site = format_args!("{:#x}", target_site), thunk_va = format_args!("{:#x}", thunk_va), "patched heap alloc fallback at 0x141a65f50");
        }
    }
}

unsafe fn patch_heap_alloc_buffer_guard(base: usize, info: &ImageInfo) {
    let target_rva = 0x1a65f9e;
    let target_site = base + target_rva;
    let patch_len = 11;
    if target_rva + patch_len >= info.size_of_image as usize {
        return;
    }
    let expected = [0x48, 0x89, 0xc1, 0x31, 0xd2, 0x49, 0x89, 0xf8, 0x48, 0x89, 0x06];
    let slice = unsafe { std::slice::from_raw_parts(target_site as *const u8, patch_len) };
    if slice != expected {
        return;
    }

    let thunk_mem = match alloc_near(base, info.size_of_image as usize, 4096) {
        Ok(p) => p,
        Err(_) => return,
    };
    let thunk_va = thunk_mem as usize;
    let target_continue = target_site + patch_len;
    let epilogue_site = base + 0x1a65ff0;
    let helper_fn = victory_alloc_fallback_heap as *const () as usize;

    let mut thunk = Vec::with_capacity(64);
    // test rax, rax
    thunk.extend_from_slice(&[0x48, 0x85, 0xc0]);
    // jnz .Lhas_rax (placeholder)
    let jnz_has_rax = thunk.len();
    thunk.extend_from_slice(&[0x75, 0x00]);

    // push rdi
    thunk.push(0x57);
    // push rsi
    thunk.push(0x56);
    // mov rcx, r15
    thunk.extend_from_slice(&[0x4c, 0x89, 0xf9]);
    // sub rsp, 40
    thunk.extend_from_slice(&[0x48, 0x83, 0xec, 0x28]);
    // mov r11, helper_fn
    thunk.extend_from_slice(&[0x49, 0xbb]);
    thunk.extend_from_slice(&(helper_fn as u64).to_le_bytes());
    // call r11
    thunk.extend_from_slice(&[0x41, 0xff, 0xd3]);
    // add rsp, 40
    thunk.extend_from_slice(&[0x48, 0x83, 0xc4, 0x28]);
    // pop rsi
    thunk.push(0x5e);
    // pop rdi
    thunk.push(0x5f);

    // test rax, rax
    thunk.extend_from_slice(&[0x48, 0x85, 0xc0]);
    // jz .Lepilogue (placeholder)
    let jz_epilogue = thunk.len();
    thunk.extend_from_slice(&[0x74, 0x00]);

    // .Lhas_rax:
    let has_rax_off = thunk.len();
    thunk[jnz_has_rax + 1] = (has_rax_off - (jnz_has_rax + 2)) as u8;

    // mov rcx, rax
    thunk.extend_from_slice(&[0x48, 0x89, 0xc1]);
    // xor edx, edx
    thunk.extend_from_slice(&[0x31, 0xd2]);
    // mov r8, rdi
    thunk.extend_from_slice(&[0x49, 0x89, 0xf8]);
    // mov [rsi], rax
    thunk.extend_from_slice(&[0x48, 0x89, 0x06]);

    // jmp target_continue (0x141a65fa9)
    let next_ip = thunk_va + thunk.len() + 5;
    let disp = (target_continue as i64 - next_ip as i64) as i32;
    thunk.push(0xe9);
    thunk.extend_from_slice(&disp.to_le_bytes());

    // .Lepilogue:
    let epilogue_off = thunk.len();
    thunk[jz_epilogue + 1] = (epilogue_off - (jz_epilogue + 2)) as u8;

    // jmp epilogue_site (0x141a65ff0)
    let next_ip2 = thunk_va + thunk.len() + 5;
    let disp2 = (epilogue_site as i64 - next_ip2 as i64) as i32;
    thunk.push(0xe9);
    thunk.extend_from_slice(&disp2.to_le_bytes());

    #[cfg(unix)]
    unsafe {
        std::ptr::copy_nonoverlapping(thunk.as_ptr(), thunk_mem, thunk.len());
        libc::mprotect(thunk_mem as *mut libc::c_void, 4096, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC);
        let aligned_start = target_site & !4095;
        let aligned_len = (target_site + patch_len - aligned_start).next_multiple_of(4096);
        if libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) == 0 {
            let target_mut = std::slice::from_raw_parts_mut(target_site as *mut u8, patch_len);
            let disp = (thunk_va as i64 - (target_site as i64 + 5)) as i32;
            target_mut[0] = 0xe9;
            target_mut[1..5].copy_from_slice(&disp.to_le_bytes());
            target_mut[5..patch_len].fill(0x90);
            libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_EXEC);
            tracing::info!(target_site = format_args!("{:#x}", target_site), thunk_va = format_args!("{:#x}", thunk_va), "patched heap alloc buffer guard at 0x141a65f9e");
        }
    }
}

unsafe fn patch_pool_alloc_buffer_guard(base: usize, info: &ImageInfo) {
    let target_rva = 0x17abaff;
    let target_site = base + target_rva;
    let patch_len = 10;
    if target_rva + patch_len >= info.size_of_image as usize {
        return;
    }
    let expected = [0x48, 0x89, 0x43, 0x08, 0x89, 0x73, 0x10, 0x89, 0x7b, 0x14];
    let slice = unsafe { std::slice::from_raw_parts(target_site as *const u8, patch_len) };
    if slice != expected {
        return;
    }

    let thunk_mem = match alloc_near(base, info.size_of_image as usize, 4096) {
        Ok(p) => p,
        Err(_) => return,
    };
    let thunk_va = thunk_mem as usize;
    let target_continue = target_site + patch_len;
    let helper_fn = victory_alloc_fallback_heap as *const () as usize;

    let mut thunk = Vec::with_capacity(64);
    // test rax, rax
    thunk.extend_from_slice(&[0x48, 0x85, 0xc0]);
    // jnz .Lhas_rax (placeholder)
    let jnz_has_rax = thunk.len();
    thunk.extend_from_slice(&[0x75, 0x00]);

    // push rbx
    thunk.push(0x53);
    // push rdi
    thunk.push(0x57);
    // push rsi
    thunk.push(0x56);
    // push rdx
    thunk.push(0x52);
    // mov rcx, rsi
    thunk.extend_from_slice(&[0x48, 0x89, 0xf1]);
    // imul rcx, rdi
    thunk.extend_from_slice(&[0x48, 0x0f, 0xaf, 0xcf]);
    // sub rsp, 32 (shadow space, keeping 16-byte alignment)
    thunk.extend_from_slice(&[0x48, 0x83, 0xec, 0x20]);
    // mov r11, helper_fn
    thunk.extend_from_slice(&[0x49, 0xbb]);
    thunk.extend_from_slice(&(helper_fn as u64).to_le_bytes());
    // call r11
    thunk.extend_from_slice(&[0x41, 0xff, 0xd3]);
    // add rsp, 32
    thunk.extend_from_slice(&[0x48, 0x83, 0xc4, 0x20]);
    // pop rdx
    thunk.push(0x5a);
    // pop rsi
    thunk.push(0x5e);
    // pop rdi
    thunk.push(0x5f);
    // pop rbx
    thunk.push(0x5b);

    // .Lhas_rax:
    let has_rax_off = thunk.len();
    thunk[jnz_has_rax + 1] = (has_rax_off - (jnz_has_rax + 2)) as u8;

    // mov [rbx + 0x8], rax
    thunk.extend_from_slice(&[0x48, 0x89, 0x43, 0x08]);
    // mov [rbx + 0x10], esi
    thunk.extend_from_slice(&[0x89, 0x73, 0x10]);
    // mov [rbx + 0x14], edi
    thunk.extend_from_slice(&[0x89, 0x7b, 0x14]);

    // jmp target_continue (0x1417abb09)
    let next_ip = thunk_va + thunk.len() + 5;
    let disp = (target_continue as i64 - next_ip as i64) as i32;
    thunk.push(0xe9);
    thunk.extend_from_slice(&disp.to_le_bytes());

    #[cfg(unix)]
    unsafe {
        std::ptr::copy_nonoverlapping(thunk.as_ptr(), thunk_mem, thunk.len());
        libc::mprotect(thunk_mem as *mut libc::c_void, 4096, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC);
        let aligned_start = target_site & !4095;
        let aligned_len = (target_site + patch_len - aligned_start).next_multiple_of(4096);
        if libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) == 0 {
            let target_mut = std::slice::from_raw_parts_mut(target_site as *mut u8, patch_len);
            let disp = (thunk_va as i64 - (target_site as i64 + 5)) as i32;
            target_mut[0] = 0xe9;
            target_mut[1..5].copy_from_slice(&disp.to_le_bytes());
            target_mut[5..patch_len].fill(0x90);
            libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_EXEC);
            tracing::info!(target_site = format_args!("{:#x}", target_site), thunk_va = format_args!("{:#x}", thunk_va), "patched pool alloc buffer guard at 0x1417abaff");
        }
    }
}

unsafe fn patch_queue_config_null_guard(base: usize, info: &ImageInfo) {
    let target_rva = 0x59518c6;
    let target_site = base + target_rva;
    let patch_len = 0x83; // 131 bytes up to 0x145951949
    if target_rva + patch_len >= info.size_of_image as usize {
        return;
    }
    let expected = [
        0x48, 0x8b, 0x05, 0xc3, 0xb6, 0x26, 0x05, 0x0f, 0xb7, 0x40, 0x0c, 0x66, 0x89, 0x05, 0x0e, 0xd7,
    ];
    let slice = unsafe { std::slice::from_raw_parts(target_site as *const u8, expected.len()) };
    if slice != expected {
        return;
    }

    let thunk_mem = match alloc_near(base, info.size_of_image as usize, 4096) {
        Ok(p) => p,
        Err(_) => return,
    };
    let thunk_va = thunk_mem as usize;

    let items: [(usize, usize); 7] = [
        (0xabbcf90, 0x875efe6),
        (0xabbd518, 0x875efec),
        (0xabbd420, 0x875efee),
        (0xabbd4f8, 0x875eff4),
        (0xabbec20, 0x875f004),
        (0xabbed78, 0x875f00c),
        (0xabbece0, 0x875f014),
    ];

    let mut thunk = Vec::with_capacity(512);
    for (src_rva, dst_rva) in items {
        let src_va = base + src_rva;
        let dst_va = base + dst_rva;

        // movabs r11, src_va
        thunk.extend_from_slice(&[0x49, 0xbb]);
        thunk.extend_from_slice(&(src_va as u64).to_le_bytes());
        // mov r10, [r11]
        thunk.extend_from_slice(&[0x4d, 0x8b, 0x13]);
        // test r10, r10
        thunk.extend_from_slice(&[0x4d, 0x85, 0xd2]);
        // je +31 (.Lzero)
        thunk.extend_from_slice(&[0x74, 0x1f]);
        // cmp r10, 0x1000
        thunk.extend_from_slice(&[0x49, 0x81, 0xfa, 0x00, 0x10, 0x00, 0x00]);
        // jb +22 (.Lzero)
        thunk.extend_from_slice(&[0x72, 0x16]);
        // movabs r11, 0xffff800000000000
        thunk.extend_from_slice(&[0x49, 0xbb, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0xff, 0xff]);
        // test r11, r10
        thunk.extend_from_slice(&[0x4d, 0x85, 0xd3]);
        // jne +7 (.Lzero)
        thunk.extend_from_slice(&[0x75, 0x07]);
        // movzx eax, word ptr [r10 + 0xc]
        thunk.extend_from_slice(&[0x41, 0x0f, 0xb7, 0x42, 0x0c]);
        // jmp +2 (.Lstore)
        thunk.extend_from_slice(&[0xeb, 0x02]);
        // .Lzero: xor eax, eax
        thunk.extend_from_slice(&[0x31, 0xc0]);
        // .Lstore: movabs r11, dst_va
        thunk.extend_from_slice(&[0x49, 0xbb]);
        thunk.extend_from_slice(&(dst_va as u64).to_le_bytes());
        // mov [r11], ax
        thunk.extend_from_slice(&[0x66, 0x41, 0x89, 0x03]);
    }

    // add rsp, 0x28
    thunk.extend_from_slice(&[0x48, 0x83, 0xc4, 0x28]);
    // ret
    thunk.push(0xc3);

    #[cfg(unix)]
    unsafe {
        std::ptr::copy_nonoverlapping(thunk.as_ptr(), thunk_mem, thunk.len());
        libc::mprotect(thunk_mem as *mut libc::c_void, 4096, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC);
        let aligned_start = target_site & !4095;
        let aligned_len = (target_site + patch_len - aligned_start).next_multiple_of(4096);
        if libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) == 0 {
            let target_mut = std::slice::from_raw_parts_mut(target_site as *mut u8, patch_len);
            let disp = (thunk_va as i64 - (target_site as i64 + 5)) as i32;
            target_mut[0] = 0xe9;
            target_mut[1..5].copy_from_slice(&disp.to_le_bytes());
            target_mut[5..patch_len].fill(0x90);
            libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_EXEC);
            tracing::info!(target_site = format_args!("{:#x}", target_site), thunk_va = format_args!("{:#x}", thunk_va), "patched queue config null guard at 0x1459518c6");
        }
    }
}

unsafe fn patch_worker_throttle_null_guard(base: usize, info: &ImageInfo) {
    let target_rva = 0x1d67955;
    let target_site = base + target_rva;
    let patch_len = 10;
    if target_rva + patch_len >= info.size_of_image as usize {
        return;
    }
    let expected = [0x48, 0x8b, 0x05, 0x44, 0x0b, 0xb9, 0x07, 0x8b, 0x40, 0x0c];
    let slice = unsafe { std::slice::from_raw_parts(target_site as *const u8, patch_len) };
    if slice != expected {
        return;
    }

    let thunk_mem = match alloc_near(base, info.size_of_image as usize, 4096) {
        Ok(p) => p,
        Err(_) => return,
    };
    let thunk_va = thunk_mem as usize;
    let src_va = base + 0x98f84a0;
    let target_continue = base + 0x1d6795f;
    let target_skip = base + 0x1d6798e;

    let mut thunk = Vec::with_capacity(128);
    // movabs r11, src_va
    thunk.extend_from_slice(&[0x49, 0xbb]);
    thunk.extend_from_slice(&(src_va as u64).to_le_bytes());
    // mov rax, [r11]
    thunk.extend_from_slice(&[0x49, 0x8b, 0x03]);
    // test rax, rax
    thunk.extend_from_slice(&[0x48, 0x85, 0xc0]);
    // jz .Lskip (placeholder)
    let jz_skip_off = thunk.len();
    thunk.extend_from_slice(&[0x74, 0x00]);

    // cmp rax, 0x1000
    thunk.extend_from_slice(&[0x48, 0x81, 0xf8, 0x00, 0x10, 0x00, 0x00]);
    // jb .Lskip (placeholder)
    let jb_skip_off = thunk.len();
    thunk.extend_from_slice(&[0x72, 0x00]);

    // movabs r11, 0xffff800000000000
    thunk.extend_from_slice(&[0x49, 0xbb, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0xff, 0xff]);
    // test r11, rax
    thunk.extend_from_slice(&[0x49, 0x85, 0xc3]);
    // jnz .Lskip (placeholder)
    let jnz_skip_off = thunk.len();
    thunk.extend_from_slice(&[0x75, 0x00]);

    // .Lvalid:
    // mov eax, [rax + 0xc]
    thunk.extend_from_slice(&[0x8b, 0x40, 0x0c]);
    // jmp target_continue (0x141d6795f)
    let next_ip = thunk_va + thunk.len() + 5;
    let disp_continue = (target_continue as i64 - next_ip as i64) as i32;
    thunk.push(0xe9);
    thunk.extend_from_slice(&disp_continue.to_le_bytes());

    // .Lskip:
    let skip_off = thunk.len();
    thunk[jz_skip_off + 1] = (skip_off - (jz_skip_off + 2)) as u8;
    thunk[jb_skip_off + 1] = (skip_off - (jb_skip_off + 2)) as u8;
    thunk[jnz_skip_off + 1] = (skip_off - (jnz_skip_off + 2)) as u8;

    // jmp target_skip (0x141d6798e)
    let next_ip_skip = thunk_va + thunk.len() + 5;
    let disp_skip = (target_skip as i64 - next_ip_skip as i64) as i32;
    thunk.push(0xe9);
    thunk.extend_from_slice(&disp_skip.to_le_bytes());

    #[cfg(unix)]
    unsafe {
        std::ptr::copy_nonoverlapping(thunk.as_ptr(), thunk_mem, thunk.len());
        libc::mprotect(thunk_mem as *mut libc::c_void, 4096, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC);
        let aligned_start = target_site & !4095;
        let aligned_len = (target_site + patch_len - aligned_start).next_multiple_of(4096);
        if libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) == 0 {
            let target_mut = std::slice::from_raw_parts_mut(target_site as *mut u8, patch_len);
            let disp = (thunk_va as i64 - (target_site as i64 + 5)) as i32;
            target_mut[0] = 0xe9;
            target_mut[1..5].copy_from_slice(&disp.to_le_bytes());
            target_mut[5..patch_len].fill(0x90);
            libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_EXEC);
            tracing::info!(target_site = format_args!("{:#x}", target_site), thunk_va = format_args!("{:#x}", thunk_va), "patched worker throttle null guard at 0x141d67955");
        }
    }
}

unsafe fn patch_task_queue_size_null_guard(base: usize, info: &ImageInfo) {
    let target_rva = 0x5c8fed9;
    let target_site = base + target_rva;
    let patch_len = 5;
    if target_rva + patch_len >= info.size_of_image as usize {
        return;
    }
    let expected = [0x8b, 0x71, 0x0c, 0x39, 0xf0];
    let slice = unsafe { std::slice::from_raw_parts(target_site as *const u8, patch_len) };
    if slice != expected {
        return;
    }

    let thunk_mem = match alloc_near(base, info.size_of_image as usize, 4096) {
        Ok(p) => p,
        Err(_) => return,
    };
    let thunk_va = thunk_mem as usize;
    let target_continue = base + 0x5c8fede;

    let mut thunk = Vec::with_capacity(64);
    // test rcx, rcx
    thunk.extend_from_slice(&[0x48, 0x85, 0xc9]);
    // jz .Lzero (placeholder)
    let jz_off = thunk.len();
    thunk.extend_from_slice(&[0x74, 0x00]);

    // cmp rcx, 0x1000
    thunk.extend_from_slice(&[0x48, 0x81, 0xf9, 0x00, 0x10, 0x00, 0x00]);
    // jb .Lzero (placeholder)
    let jb_off = thunk.len();
    thunk.extend_from_slice(&[0x72, 0x00]);

    // movabs r11, 0xffff800000000000
    thunk.extend_from_slice(&[0x49, 0xbb, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0xff, 0xff]);
    // test r11, rcx
    thunk.extend_from_slice(&[0x49, 0x85, 0xcb]);
    // jnz .Lzero (placeholder)
    let jnz_off = thunk.len();
    thunk.extend_from_slice(&[0x75, 0x00]);

    // mov esi, [rcx + 0xc]
    thunk.extend_from_slice(&[0x8b, 0x71, 0x0c]);
    // jmp .Lcmp (placeholder)
    let jmp_cmp_off = thunk.len();
    thunk.extend_from_slice(&[0xeb, 0x00]);

    // .Lzero:
    let zero_off = thunk.len();
    thunk[jz_off + 1] = (zero_off - (jz_off + 2)) as u8;
    thunk[jb_off + 1] = (zero_off - (jb_off + 2)) as u8;
    thunk[jnz_off + 1] = (zero_off - (jnz_off + 2)) as u8;

    // xor esi, esi
    thunk.extend_from_slice(&[0x31, 0xf6]);

    // .Lcmp:
    let cmp_off = thunk.len();
    thunk[jmp_cmp_off + 1] = (cmp_off - (jmp_cmp_off + 2)) as u8;

    // cmp eax, esi
    thunk.extend_from_slice(&[0x39, 0xf0]);

    // jmp target_continue (0x145c8fede)
    let next_ip = thunk_va + thunk.len() + 5;
    let disp = (target_continue as i64 - next_ip as i64) as i32;
    thunk.push(0xe9);
    thunk.extend_from_slice(&disp.to_le_bytes());

    #[cfg(unix)]
    unsafe {
        std::ptr::copy_nonoverlapping(thunk.as_ptr(), thunk_mem, thunk.len());
        libc::mprotect(thunk_mem as *mut libc::c_void, 4096, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC);
        let aligned_start = target_site & !4095;
        let aligned_len = (target_site + patch_len - aligned_start).next_multiple_of(4096);
        if libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) == 0 {
            let target_mut = std::slice::from_raw_parts_mut(target_site as *mut u8, patch_len);
            let disp = (thunk_va as i64 - (target_site as i64 + 5)) as i32;
            target_mut[0] = 0xe9;
            target_mut[1..5].copy_from_slice(&disp.to_le_bytes());
            libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_EXEC);
            tracing::info!(target_site = format_args!("{:#x}", target_site), thunk_va = format_args!("{:#x}", thunk_va), "patched task queue size null guard at 0x145c8fed9");
        }
    }
}

unsafe fn patch_buffer_resize_null_guard(base: usize, info: &ImageInfo) {
    let target_rva = 0x5b49c59;
    let target_site = base + target_rva;
    let patch_len = 10;
    if target_rva + patch_len >= info.size_of_image as usize {
        return;
    }
    let expected = [0x48, 0x8b, 0x05, 0x28, 0x91, 0xac, 0x01, 0x8b, 0x48, 0x0c];
    let slice = unsafe { std::slice::from_raw_parts(target_site as *const u8, patch_len) };
    if slice != expected {
        return;
    }

    let thunk_mem = match alloc_near(base, info.size_of_image as usize, 4096) {
        Ok(p) => p,
        Err(_) => return,
    };
    let thunk_va = thunk_mem as usize;
    let src_va = base + 0x7612d88;
    let target_continue = base + 0x5b49c63;
    let target_skip = base + 0x5b49c70;

    let mut thunk = Vec::with_capacity(128);
    // movabs r11, src_va
    thunk.extend_from_slice(&[0x49, 0xbb]);
    thunk.extend_from_slice(&(src_va as u64).to_le_bytes());
    // mov rax, [r11]
    thunk.extend_from_slice(&[0x49, 0x8b, 0x03]);
    // test rax, rax
    thunk.extend_from_slice(&[0x48, 0x85, 0xc0]);
    // jz .Lskip (placeholder)
    let jz_skip_off = thunk.len();
    thunk.extend_from_slice(&[0x74, 0x00]);

    // cmp rax, 0x1000
    thunk.extend_from_slice(&[0x48, 0x81, 0xf8, 0x00, 0x10, 0x00, 0x00]);
    // jb .Lskip (placeholder)
    let jb_skip_off = thunk.len();
    thunk.extend_from_slice(&[0x72, 0x00]);

    // movabs r11, 0xffff800000000000
    thunk.extend_from_slice(&[0x49, 0xbb, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0xff, 0xff]);
    // test r11, rax
    thunk.extend_from_slice(&[0x49, 0x85, 0xc3]);
    // jnz .Lskip (placeholder)
    let jnz_skip_off = thunk.len();
    thunk.extend_from_slice(&[0x75, 0x00]);

    // .Lvalid:
    // mov ecx, [rax + 0xc]
    thunk.extend_from_slice(&[0x8b, 0x48, 0x0c]);
    // jmp target_continue (0x145b49c63)
    let next_ip = thunk_va + thunk.len() + 5;
    let disp_continue = (target_continue as i64 - next_ip as i64) as i32;
    thunk.push(0xe9);
    thunk.extend_from_slice(&disp_continue.to_le_bytes());

    // .Lskip:
    let skip_off = thunk.len();
    thunk[jz_skip_off + 1] = (skip_off - (jz_skip_off + 2)) as u8;
    thunk[jb_skip_off + 1] = (skip_off - (jb_skip_off + 2)) as u8;
    thunk[jnz_skip_off + 1] = (skip_off - (jnz_skip_off + 2)) as u8;

    // jmp target_skip (0x145b49c70)
    let next_ip_skip = thunk_va + thunk.len() + 5;
    let disp_skip = (target_skip as i64 - next_ip_skip as i64) as i32;
    thunk.push(0xe9);
    thunk.extend_from_slice(&disp_skip.to_le_bytes());

    #[cfg(unix)]
    unsafe {
        std::ptr::copy_nonoverlapping(thunk.as_ptr(), thunk_mem, thunk.len());
        libc::mprotect(thunk_mem as *mut libc::c_void, 4096, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC);
        let aligned_start = target_site & !4095;
        let aligned_len = (target_site + patch_len - aligned_start).next_multiple_of(4096);
        if libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) == 0 {
            let target_mut = std::slice::from_raw_parts_mut(target_site as *mut u8, patch_len);
            let disp = (thunk_va as i64 - (target_site as i64 + 5)) as i32;
            target_mut[0] = 0xe9;
            target_mut[1..5].copy_from_slice(&disp.to_le_bytes());
            target_mut[5..patch_len].fill(0x90);
            libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_EXEC);
            tracing::info!(target_site = format_args!("{:#x}", target_site), thunk_va = format_args!("{:#x}", thunk_va), "patched buffer resize null guard at 0x145b49c59");
        }
    }
}

unsafe fn patch_node_unlink_guard(base: usize, info: &ImageInfo) {
    let target_rva = 0x17f6fdd;
    let target_site = base + target_rva;
    let patch_len = 18;
    if target_rva + patch_len >= info.size_of_image as usize {
        return;
    }
    let expected = [
        0x48, 0x85, 0xd2, 0x74, 0x04, 0x48, 0x89, 0x42, 0x18, 0x48, 0x85, 0xc0, 0x74, 0x04, 0x48,
        0x89, 0x50, 0x10,
    ];
    let slice = unsafe { std::slice::from_raw_parts(target_site as *const u8, patch_len) };
    if slice != expected {
        return;
    }

    let thunk_mem = match alloc_near(base, info.size_of_image as usize, 4096) {
        Ok(p) => p,
        Err(_) => return,
    };
    let thunk_va = thunk_mem as usize;

    let mut thunk = Vec::with_capacity(128);

    // test rdx, rdx
    thunk.extend_from_slice(&[0x48, 0x85, 0xd2]);
    // jz .Lcheck_rax
    let jz_rax_1 = thunk.len();
    thunk.extend_from_slice(&[0x74, 0x00]);

    // test dl, 7
    thunk.extend_from_slice(&[0xf6, 0xc2, 0x07]);
    // jnz .Lcheck_rax
    let jnz_rax_2 = thunk.len();
    thunk.extend_from_slice(&[0x75, 0x00]);

    // cmp rdx, 0x10000
    thunk.extend_from_slice(&[0x48, 0x81, 0xfa, 0x00, 0x00, 0x01, 0x00]);
    // jb .Lcheck_rax
    let jb_rax_3 = thunk.len();
    thunk.extend_from_slice(&[0x72, 0x00]);

    // movabs r11, 0xffff800000000000
    thunk.extend_from_slice(&[0x49, 0xbb, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0xff, 0xff]);
    // test r11, rdx
    thunk.extend_from_slice(&[0x49, 0x85, 0xd3]);
    // jnz .Lcheck_rax
    let jnz_rax_4 = thunk.len();
    thunk.extend_from_slice(&[0x75, 0x00]);

    // mov [rdx + 0x18], rax
    thunk.extend_from_slice(&[0x48, 0x89, 0x42, 0x18]);

    // .Lcheck_rax:
    let check_rax_off = thunk.len();
    thunk[jz_rax_1 + 1] = (check_rax_off - (jz_rax_1 + 2)) as u8;
    thunk[jnz_rax_2 + 1] = (check_rax_off - (jnz_rax_2 + 2)) as u8;
    thunk[jb_rax_3 + 1] = (check_rax_off - (jb_rax_3 + 2)) as u8;
    thunk[jnz_rax_4 + 1] = (check_rax_off - (jnz_rax_4 + 2)) as u8;

    // test rax, rax
    thunk.extend_from_slice(&[0x48, 0x85, 0xc0]);
    // jz .Ldone
    let jz_done_1 = thunk.len();
    thunk.extend_from_slice(&[0x74, 0x00]);

    // test al, 7
    thunk.extend_from_slice(&[0xa8, 0x07]);
    // jnz .Ldone
    let jnz_done_2 = thunk.len();
    thunk.extend_from_slice(&[0x75, 0x00]);

    // cmp rax, 0x10000
    thunk.extend_from_slice(&[0x48, 0x81, 0xf8, 0x00, 0x00, 0x01, 0x00]);
    // jb .Ldone
    let jb_done_3 = thunk.len();
    thunk.extend_from_slice(&[0x72, 0x00]);

    // movabs r11, 0xffff800000000000
    thunk.extend_from_slice(&[0x49, 0xbb, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0xff, 0xff]);
    // test r11, rax
    thunk.extend_from_slice(&[0x49, 0x85, 0xc3]);
    // jnz .Ldone
    let jnz_done_4 = thunk.len();
    thunk.extend_from_slice(&[0x75, 0x00]);

    // mov [rax + 0x10], rdx
    thunk.extend_from_slice(&[0x48, 0x89, 0x50, 0x10]);

    // .Ldone:
    let done_off = thunk.len();
    thunk[jz_done_1 + 1] = (done_off - (jz_done_1 + 2)) as u8;
    thunk[jnz_done_2 + 1] = (done_off - (jnz_done_2 + 2)) as u8;
    thunk[jb_done_3 + 1] = (done_off - (jb_done_3 + 2)) as u8;
    thunk[jnz_done_4 + 1] = (done_off - (jnz_done_4 + 2)) as u8;

    // ret
    thunk.push(0xc3);

    #[cfg(unix)]
    unsafe {
        std::ptr::copy_nonoverlapping(thunk.as_ptr(), thunk_mem, thunk.len());
        libc::mprotect(thunk_mem as *mut libc::c_void, 4096, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC);
        let aligned_start = target_site & !4095;
        let aligned_len = (target_site + patch_len - aligned_start).next_multiple_of(4096);
        if libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) == 0 {
            let target_mut = std::slice::from_raw_parts_mut(target_site as *mut u8, patch_len);
            let disp = (thunk_va as i64 - (target_site as i64 + 5)) as i32;
            target_mut[0] = 0xe9;
            target_mut[1..5].copy_from_slice(&disp.to_le_bytes());
            target_mut[5..patch_len].fill(0x90);
            libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_EXEC);
            tracing::info!(target_site = format_args!("{:#x}", target_site), thunk_va = format_args!("{:#x}", thunk_va), "patched node unlink guard at 0x1417f6fdd");
        }
    }
}

unsafe fn patch_worker_capacity_null_guard(base: usize, info: &ImageInfo) {
    let target_rva = 0x5bb1017;
    let target_site = base + target_rva;
    let patch_len = 10;
    if target_rva + patch_len >= info.size_of_image as usize {
        return;
    }
    let expected = [0x48, 0x8b, 0x05, 0x5a, 0x04, 0xd4, 0x03, 0x8b, 0x50, 0x0c];
    let slice = unsafe { std::slice::from_raw_parts(target_site as *const u8, patch_len) };
    if slice != expected {
        return;
    }

    let thunk_mem = match alloc_near(base, info.size_of_image as usize, 4096) {
        Ok(p) => p,
        Err(_) => return,
    };
    let thunk_va = thunk_mem as usize;
    let src_va = base + 0x98f1478;
    let target_continue = base + 0x5bb1021;
    let target_skip = base + 0x5bb1035;

    let mut thunk = Vec::with_capacity(128);
    // movabs r11, src_va
    thunk.extend_from_slice(&[0x49, 0xbb]);
    thunk.extend_from_slice(&(src_va as u64).to_le_bytes());
    // mov rax, [r11]
    thunk.extend_from_slice(&[0x49, 0x8b, 0x03]);
    // test rax, rax
    thunk.extend_from_slice(&[0x48, 0x85, 0xc0]);
    // jz .Lskip (placeholder)
    let jz_skip_off = thunk.len();
    thunk.extend_from_slice(&[0x74, 0x00]);

    // cmp rax, 0x1000
    thunk.extend_from_slice(&[0x48, 0x81, 0xf8, 0x00, 0x10, 0x00, 0x00]);
    // jb .Lskip (placeholder)
    let jb_skip_off = thunk.len();
    thunk.extend_from_slice(&[0x72, 0x00]);

    // movabs r11, 0xffff800000000000
    thunk.extend_from_slice(&[0x49, 0xbb, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0xff, 0xff]);
    // test r11, rax
    thunk.extend_from_slice(&[0x49, 0x85, 0xc3]);
    // jnz .Lskip (placeholder)
    let jnz_skip_off = thunk.len();
    thunk.extend_from_slice(&[0x75, 0x00]);

    // .Lvalid:
    // mov edx, [rax + 0xc]
    thunk.extend_from_slice(&[0x8b, 0x50, 0x0c]);
    // jmp target_continue (0x145bb1021)
    let next_ip = thunk_va + thunk.len() + 5;
    let disp_continue = (target_continue as i64 - next_ip as i64) as i32;
    thunk.push(0xe9);
    thunk.extend_from_slice(&disp_continue.to_le_bytes());

    // .Lskip:
    let skip_off = thunk.len();
    thunk[jz_skip_off + 1] = (skip_off - (jz_skip_off + 2)) as u8;
    thunk[jb_skip_off + 1] = (skip_off - (jb_skip_off + 2)) as u8;
    thunk[jnz_skip_off + 1] = (skip_off - (jnz_skip_off + 2)) as u8;

    // jmp target_skip (0x145bb1035)
    let next_ip_skip = thunk_va + thunk.len() + 5;
    let disp_skip = (target_skip as i64 - next_ip_skip as i64) as i32;
    thunk.push(0xe9);
    thunk.extend_from_slice(&disp_skip.to_le_bytes());

    #[cfg(unix)]
    unsafe {
        std::ptr::copy_nonoverlapping(thunk.as_ptr(), thunk_mem, thunk.len());
        libc::mprotect(thunk_mem as *mut libc::c_void, 4096, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC);
        let aligned_start = target_site & !4095;
        let aligned_len = (target_site + patch_len - aligned_start).next_multiple_of(4096);
        if libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) == 0 {
            let target_mut = std::slice::from_raw_parts_mut(target_site as *mut u8, patch_len);
            let disp = (thunk_va as i64 - (target_site as i64 + 5)) as i32;
            target_mut[0] = 0xe9;
            target_mut[1..5].copy_from_slice(&disp.to_le_bytes());
            target_mut[5..patch_len].fill(0x90);
            libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_EXEC);
            tracing::info!(target_site = format_args!("{:#x}", target_site), thunk_va = format_args!("{:#x}", thunk_va), "patched worker capacity null guard at 0x145bb1017");
        }
    }
}

unsafe fn patch_worker_pool_getter_null_guard(base: usize, info: &ImageInfo) {
    let target_rva = 0x5550930;
    let target_site = base + target_rva;
    let patch_len = 11;
    if target_rva + patch_len >= info.size_of_image as usize {
        return;
    }
    let expected = [0x48, 0x8b, 0x05, 0x41, 0x0b, 0x3a, 0x04, 0x8b, 0x40, 0x0c, 0xc3];
    let slice = unsafe { std::slice::from_raw_parts(target_site as *const u8, patch_len) };
    if slice != expected {
        return;
    }

    let thunk_mem = match alloc_near(base, info.size_of_image as usize, 4096) {
        Ok(p) => p,
        Err(_) => return,
    };
    let thunk_va = thunk_mem as usize;
    let src_va = base + 0x98f1478;

    let mut thunk = Vec::with_capacity(64);
    // movabs r11, src_va
    thunk.extend_from_slice(&[0x49, 0xbb]);
    thunk.extend_from_slice(&(src_va as u64).to_le_bytes());
    // mov rax, [r11]
    thunk.extend_from_slice(&[0x49, 0x8b, 0x03]);
    // test rax, rax
    thunk.extend_from_slice(&[0x48, 0x85, 0xc0]);
    // jz .Lzero
    let jz_off = thunk.len();
    thunk.extend_from_slice(&[0x74, 0x00]);

    // cmp rax, 0x1000
    thunk.extend_from_slice(&[0x48, 0x81, 0xf8, 0x00, 0x10, 0x00, 0x00]);
    // jb .Lzero
    let jb_off = thunk.len();
    thunk.extend_from_slice(&[0x72, 0x00]);

    // movabs r11, 0xffff800000000000
    thunk.extend_from_slice(&[0x49, 0xbb, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0xff, 0xff]);
    // test r11, rax
    thunk.extend_from_slice(&[0x49, 0x85, 0xc3]);
    // jnz .Lzero
    let jnz_off = thunk.len();
    thunk.extend_from_slice(&[0x75, 0x00]);

    // mov eax, [rax + 0xc]
    thunk.extend_from_slice(&[0x8b, 0x40, 0x0c]);
    // ret
    thunk.push(0xc3);

    // .Lzero:
    let zero_off = thunk.len();
    thunk[jz_off + 1] = (zero_off - (jz_off + 2)) as u8;
    thunk[jb_off + 1] = (zero_off - (jb_off + 2)) as u8;
    thunk[jnz_off + 1] = (zero_off - (jnz_off + 2)) as u8;

    // xor eax, eax
    thunk.extend_from_slice(&[0x31, 0xc0]);
    // ret
    thunk.push(0xc3);

    #[cfg(unix)]
    unsafe {
        std::ptr::copy_nonoverlapping(thunk.as_ptr(), thunk_mem, thunk.len());
        libc::mprotect(thunk_mem as *mut libc::c_void, 4096, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC);
        let aligned_start = target_site & !4095;
        let aligned_len = (target_site + patch_len - aligned_start).next_multiple_of(4096);
        if libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) == 0 {
            let target_mut = std::slice::from_raw_parts_mut(target_site as *mut u8, patch_len);
            let disp = (thunk_va as i64 - (target_site as i64 + 5)) as i32;
            target_mut[0] = 0xe9;
            target_mut[1..5].copy_from_slice(&disp.to_le_bytes());
            target_mut[5..patch_len].fill(0x90);
            libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_EXEC);
            tracing::info!(target_site = format_args!("{:#x}", target_site), thunk_va = format_args!("{:#x}", thunk_va), "patched worker pool getter null guard at 0x145550930");
        }
    }
}

unsafe fn patch_worker_notify_null_guard(base: usize, info: &ImageInfo) {
    let target_rva = 0x1d8969f;
    let target_site = base + target_rva;
    let patch_len = 14;
    if target_rva + patch_len >= info.size_of_image as usize {
        return;
    }
    let expected = [
        0x48, 0x8b, 0x05, 0x42, 0xb6, 0xe3, 0x05, 0x8b, 0x50, 0x0c, 0x85, 0xd2, 0x74, 0x08,
    ];
    let slice = unsafe { std::slice::from_raw_parts(target_site as *const u8, patch_len) };
    if slice != expected {
        return;
    }

    let thunk_mem = match alloc_near(base, info.size_of_image as usize, 4096) {
        Ok(p) => p,
        Err(_) => return,
    };
    let thunk_va = thunk_mem as usize;
    let src_va = base + 0x7c24ce8;
    let target_continue = base + 0x1d896ad;
    let target_skip = base + 0x1d896b5;

    let mut thunk = Vec::with_capacity(128);
    // movabs r11, src_va
    thunk.extend_from_slice(&[0x49, 0xbb]);
    thunk.extend_from_slice(&(src_va as u64).to_le_bytes());
    // mov rax, [r11]
    thunk.extend_from_slice(&[0x49, 0x8b, 0x03]);
    // test rax, rax
    thunk.extend_from_slice(&[0x48, 0x85, 0xc0]);
    // jz .Lskip (placeholder)
    let jz_skip_off = thunk.len();
    thunk.extend_from_slice(&[0x74, 0x00]);

    // cmp rax, 0x1000
    thunk.extend_from_slice(&[0x48, 0x81, 0xf8, 0x00, 0x10, 0x00, 0x00]);
    // jb .Lskip (placeholder)
    let jb_skip_off = thunk.len();
    thunk.extend_from_slice(&[0x72, 0x00]);

    // movabs r11, 0xffff800000000000
    thunk.extend_from_slice(&[0x49, 0xbb, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0xff, 0xff]);
    // test r11, rax
    thunk.extend_from_slice(&[0x49, 0x85, 0xc3]);
    // jnz .Lskip (placeholder)
    let jnz_skip_off = thunk.len();
    thunk.extend_from_slice(&[0x75, 0x00]);

    // .Lvalid:
    // mov edx, [rax + 0xc]
    thunk.extend_from_slice(&[0x8b, 0x50, 0x0c]);
    // test edx, edx
    thunk.extend_from_slice(&[0x85, 0xd2]);
    // jz .Lskip (placeholder)
    let jz_skip_2 = thunk.len();
    thunk.extend_from_slice(&[0x74, 0x00]);

    // jmp target_continue (0x141d896ad)
    let next_ip = thunk_va + thunk.len() + 5;
    let disp_continue = (target_continue as i64 - next_ip as i64) as i32;
    thunk.push(0xe9);
    thunk.extend_from_slice(&disp_continue.to_le_bytes());

    // .Lskip:
    let skip_off = thunk.len();
    thunk[jz_skip_off + 1] = (skip_off - (jz_skip_off + 2)) as u8;
    thunk[jb_skip_off + 1] = (skip_off - (jb_skip_off + 2)) as u8;
    thunk[jnz_skip_off + 1] = (skip_off - (jnz_skip_off + 2)) as u8;
    thunk[jz_skip_2 + 1] = (skip_off - (jz_skip_2 + 2)) as u8;

    // jmp target_skip (0x141d896b5)
    let next_ip_skip = thunk_va + thunk.len() + 5;
    let disp_skip = (target_skip as i64 - next_ip_skip as i64) as i32;
    thunk.push(0xe9);
    thunk.extend_from_slice(&disp_skip.to_le_bytes());

    #[cfg(unix)]
    unsafe {
        std::ptr::copy_nonoverlapping(thunk.as_ptr(), thunk_mem, thunk.len());
        libc::mprotect(thunk_mem as *mut libc::c_void, 4096, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC);
        let aligned_start = target_site & !4095;
        let aligned_len = (target_site + patch_len - aligned_start).next_multiple_of(4096);
        if libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) == 0 {
            let target_mut = std::slice::from_raw_parts_mut(target_site as *mut u8, patch_len);
            let disp = (thunk_va as i64 - (target_site as i64 + 5)) as i32;
            target_mut[0] = 0xe9;
            target_mut[1..5].copy_from_slice(&disp.to_le_bytes());
            target_mut[5..patch_len].fill(0x90);
            libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_EXEC);
            tracing::info!(target_site = format_args!("{:#x}", target_site), thunk_va = format_args!("{:#x}", thunk_va), "patched worker notify null guard at 0x141d8969f");
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "win64" fn victory_alloc_hash_node() -> *mut u8 {
    static POOL: std::sync::atomic::AtomicPtr<u8> = std::sync::atomic::AtomicPtr::new(std::ptr::null_mut());
    static OFFSET: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let mut base = POOL.load(std::sync::atomic::Ordering::Relaxed);
    if base.is_null() {
        let p = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                4 * 1024 * 1024,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_ANON | libc::MAP_PRIVATE,
                -1,
                0,
            )
        };
        if p != libc::MAP_FAILED {
            if POOL
                .compare_exchange(
                    std::ptr::null_mut(),
                    p as *mut u8,
                    std::sync::atomic::Ordering::SeqCst,
                    std::sync::atomic::Ordering::SeqCst,
                )
                .is_err()
            {
                unsafe { libc::munmap(p, 4 * 1024 * 1024); }
            }
        }
        base = POOL.load(std::sync::atomic::Ordering::SeqCst);
    }
    if !base.is_null() {
        let off = OFFSET.fetch_add(64, std::sync::atomic::Ordering::SeqCst);
        if off + 64 <= 4 * 1024 * 1024 {
            return unsafe { base.add(off) };
        }
    }
    unsafe {
        let p = libc::malloc(64);
        if !p.is_null() {
            libc::memset(p, 0, 64);
        }
        p as *mut u8
    }
}

unsafe fn patch_hash_node_alloc_fallback(base: usize, info: &ImageInfo) {
    let target_rva = 0x4db9f95;
    let target_site = base + target_rva;
    let patch_len = 41;
    if target_rva + patch_len >= info.size_of_image as usize {
        return;
    }
    let expected = [
        0x48, 0x8b, 0x41, 0x10, 0x48, 0x85, 0xc0, 0x74, 0x1f, 0x4c, 0x8b, 0x08, 0x4c, 0x8b, 0x04,
        0xd3,
    ];
    let slice = unsafe { std::slice::from_raw_parts(target_site as *const u8, expected.len()) };
    if slice != expected {
        return;
    }

    let thunk_mem = match alloc_near(base, info.size_of_image as usize, 4096) {
        Ok(p) => p,
        Err(_) => return,
    };
    let thunk_va = thunk_mem as usize;
    let helper_fn = victory_alloc_hash_node as *const () as usize;
    let target_done = base + 0x4db9f5c;

    let mut thunk = Vec::with_capacity(128);
    // mov rax, [rcx + 0x10]
    thunk.extend_from_slice(&[0x48, 0x8b, 0x41, 0x10]);
    // test rax, rax
    thunk.extend_from_slice(&[0x48, 0x85, 0xc0]);
    // jnz .Lgot_node (placeholder)
    let jnz_off = thunk.len();
    thunk.extend_from_slice(&[0x75, 0x00]);

    // Fallback allocation:
    thunk.push(0x51); // push rcx
    thunk.push(0x52); // push rdx
    thunk.push(0x53); // push rbx
    thunk.push(0x56); // push rsi
    thunk.extend_from_slice(&[0x48, 0x83, 0xec, 0x20]); // sub rsp, 32
    thunk.extend_from_slice(&[0x49, 0xbb]); // mov r11, helper_fn
    thunk.extend_from_slice(&(helper_fn as u64).to_le_bytes());
    thunk.extend_from_slice(&[0x41, 0xff, 0xd3]); // call r11
    thunk.extend_from_slice(&[0x48, 0x83, 0xc4, 0x20]); // add rsp, 32
    thunk.push(0x5e); // pop rsi
    thunk.push(0x5b); // pop rbx
    thunk.push(0x5a); // pop rdx
    thunk.push(0x59); // pop rcx

    // Fallback node insertion:
    thunk.extend_from_slice(&[0x4c, 0x8b, 0x04, 0xd3]); // mov r8, [rbx + rdx*8]
    thunk.extend_from_slice(&[0xff, 0x41, 0x08]); // inc dword ptr [rcx + 8]
    thunk.extend_from_slice(&[0x48, 0x89, 0x30]); // mov [rax], rsi
    thunk.extend_from_slice(&[0x4c, 0x89, 0x78, 0x08]); // mov [rax + 8], r15
    thunk.extend_from_slice(&[0x4c, 0x89, 0x40, 0x10]); // mov [rax + 0x10], r8
    thunk.extend_from_slice(&[0x48, 0x89, 0x04, 0xd3]); // mov [rbx + rdx*8], rax
    let next_ip1 = thunk_va + thunk.len() + 5;
    let disp_done1 = (target_done as i64 - next_ip1 as i64) as i32;
    thunk.push(0xe9);
    thunk.extend_from_slice(&disp_done1.to_le_bytes());

    // .Lgot_node:
    let got_off = thunk.len();
    thunk[jnz_off + 1] = (got_off - (jnz_off + 2)) as u8;

    thunk.extend_from_slice(&[0x4c, 0x8b, 0x08]); // mov r9, [rax]
    thunk.extend_from_slice(&[0x4c, 0x8b, 0x04, 0xd3]); // mov r8, [rbx + rdx*8]
    thunk.extend_from_slice(&[0x4c, 0x89, 0x49, 0x10]); // mov [rcx + 0x10], r9
    thunk.extend_from_slice(&[0xff, 0x41, 0x08]); // inc dword ptr [rcx + 8]
    thunk.extend_from_slice(&[0x48, 0x89, 0x30]); // mov [rax], rsi
    thunk.extend_from_slice(&[0x4c, 0x89, 0x78, 0x08]); // mov [rax + 8], r15
    thunk.extend_from_slice(&[0x4c, 0x89, 0x40, 0x10]); // mov [rax + 0x10], r8
    thunk.extend_from_slice(&[0x48, 0x89, 0x04, 0xd3]); // mov [rbx + rdx*8], rax
    let next_ip2 = thunk_va + thunk.len() + 5;
    let disp_done2 = (target_done as i64 - next_ip2 as i64) as i32;
    thunk.push(0xe9);
    thunk.extend_from_slice(&disp_done2.to_le_bytes());

    #[cfg(unix)]
    unsafe {
        std::ptr::copy_nonoverlapping(thunk.as_ptr(), thunk_mem, thunk.len());
        libc::mprotect(thunk_mem as *mut libc::c_void, 4096, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC);
        let aligned_start = target_site & !4095;
        let aligned_len = (target_site + patch_len - aligned_start).next_multiple_of(4096);
        if libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) == 0 {
            let target_mut = std::slice::from_raw_parts_mut(target_site as *mut u8, patch_len);
            let disp = (thunk_va as i64 - (target_site as i64 + 5)) as i32;
            target_mut[0] = 0xe9;
            target_mut[1..5].copy_from_slice(&disp.to_le_bytes());
            target_mut[5..patch_len].fill(0x90);
            libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_EXEC);
            tracing::info!(target_site = format_args!("{:#x}", target_site), thunk_va = format_args!("{:#x}", thunk_va), "patched hash node alloc fallback at 0x144db9f95");
        }
    }
}

unsafe fn patch_monitorx_mwaitx(base: usize, info: &ImageInfo) {
    let monitorx_sites = [0x4fb0bd7, 0x4fb0d21, 0x6e87462];
    for &rva in &monitorx_sites {
        let site = base + rva;
        if rva + 3 >= info.size_of_image as usize {
            continue;
        }
        let slice = unsafe { std::slice::from_raw_parts(site as *const u8, 3) };
        if slice == [0x0f, 0x01, 0xfa] {
            #[cfg(unix)]
            unsafe {
                let aligned_start = site & !4095;
                let aligned_len = (site + 3 - aligned_start).next_multiple_of(4096);
                if libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) == 0 {
                    let target = std::slice::from_raw_parts_mut(site as *mut u8, 3);
                    target.copy_from_slice(&[0x90, 0x90, 0x90]); // nop nop nop
                    libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_EXEC);
                    tracing::info!(site = format_args!("{:#x}", site), "patched monitorx -> nops");
                }
            }
        }
    }

    let mwaitx_sites = [0x4fb0c00, 0x4fb0d52, 0x67bd464, 0x6e874c2];
    for &rva in &mwaitx_sites {
        let site = base + rva;
        if rva + 3 >= info.size_of_image as usize {
            continue;
        }
        let slice = unsafe { std::slice::from_raw_parts(site as *const u8, 3) };
        if slice == [0x0f, 0x01, 0xfb] {
            #[cfg(unix)]
            unsafe {
                let aligned_start = site & !4095;
                let aligned_len = (site + 3 - aligned_start).next_multiple_of(4096);
                if libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) == 0 {
                    let target = std::slice::from_raw_parts_mut(site as *mut u8, 3);
                    target.copy_from_slice(&[0xf3, 0x90, 0x90]); // pause; nop
                    libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_EXEC);
                    tracing::info!(site = format_args!("{:#x}", site), "patched mwaitx -> pause; nop");
                }
            }
        }
    }
}

unsafe fn patch_vcall_rdx_deref_null_guard(base: usize, info: &ImageInfo) {
    let target_rva = 0x54f9900;
    let target_site = base + target_rva;
    if target_rva + 8 >= info.size_of_image as usize {
        return;
    }
    let slice = unsafe { std::slice::from_raw_parts(target_site as *const u8, 8) };
    if slice != [0x48, 0x8b, 0x12, 0x48, 0x85, 0xd2, 0x74, 0x16] {
        return;
    }

    let thunk_mem = match alloc_near(base, info.size_of_image as usize, 4096) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(error = %e, "failed to allocate thunk page for vcall rdx deref null guard");
            return;
        }
    };
    let thunk_va = thunk_mem as usize;

    let mut thunk = Vec::with_capacity(32);
    // test rdx, rdx
    thunk.extend_from_slice(&[0x48, 0x85, 0xd2]);
    // jz .Lret
    let jz_rdx = thunk.len();
    thunk.extend_from_slice(&[0x74, 0x00]);
    // mov rdx, [rdx]
    thunk.extend_from_slice(&[0x48, 0x8b, 0x12]);
    // test rdx, rdx
    thunk.extend_from_slice(&[0x48, 0x85, 0xd2]);
    // jz .Lret
    let jz_val = thunk.len();
    thunk.extend_from_slice(&[0x74, 0x00]);

    // proceed: jmp target_site + 8
    let proceed_site = target_site + 8;
    let next_ip = thunk_va + thunk.len() + 5;
    let disp_proceed = (proceed_site as i64 - next_ip as i64) as i32;
    thunk.push(0xe9);
    thunk.extend_from_slice(&disp_proceed.to_le_bytes());

    // .Lret:
    let lret = thunk.len();
    thunk[jz_rdx + 1] = (lret - (jz_rdx + 2)) as u8;
    thunk[jz_val + 1] = (lret - (jz_val + 2)) as u8;
    // ret
    thunk.push(0xc3);

    #[cfg(unix)]
    unsafe {
        std::ptr::copy_nonoverlapping(thunk.as_ptr(), thunk_mem, thunk.len());
        libc::mprotect(thunk_mem as *mut libc::c_void, 4096, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC);

        let aligned_start = target_site & !4095;
        let aligned_len = (target_site + 8 - aligned_start).next_multiple_of(4096);
        if libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) == 0 {
            let target_mut = std::slice::from_raw_parts_mut(target_site as *mut u8, 8);
            let rel = (thunk_va as i64) - ((target_site + 5) as i64);
            target_mut[0] = 0xe9;
            target_mut[1..5].copy_from_slice(&(rel as i32).to_le_bytes());
            target_mut[5..8].fill(0x90);
            libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_EXEC);
            tracing::info!(target_site = format_args!("{:#x}", target_site), thunk_va = format_args!("{:#x}", thunk_va), "patched vcall rdx deref null guard at 0x1454f9900");
        }
    }
}

unsafe fn patch_epilogue_zero_out_null_guard(base: usize, info: &ImageInfo) {
    let target_rva = 0x5520662;
    let target_site = base + target_rva;
    if target_rva + 6 >= info.size_of_image as usize {
        return;
    }
    let slice = unsafe { std::slice::from_raw_parts(target_site as *const u8, 6) };
    if slice != [0xc7, 0x00, 0x00, 0x00, 0x00, 0x00] {
        return;
    }

    let thunk_mem = match alloc_near(base, info.size_of_image as usize, 4096) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(error = %e, "failed to allocate thunk page for epilogue zero-out null guard");
            return;
        }
    };
    let thunk_va = thunk_mem as usize;

    let mut thunk = Vec::with_capacity(32);
    // test rax, rax
    thunk.extend_from_slice(&[0x48, 0x85, 0xc0]);
    // jz .Lskip (+6 bytes)
    thunk.extend_from_slice(&[0x74, 0x06]);
    // mov dword ptr [rax], 0
    thunk.extend_from_slice(&[0xc7, 0x00, 0x00, 0x00, 0x00, 0x00]);
    // .Lskip:
    // jmp target_site + 6 (0x5520668)
    let return_site = target_site + 6;
    let next_ip = thunk_va + thunk.len() + 5;
    let disp = (return_site as i64 - next_ip as i64) as i32;
    thunk.push(0xe9);
    thunk.extend_from_slice(&disp.to_le_bytes());

    #[cfg(unix)]
    unsafe {
        std::ptr::copy_nonoverlapping(thunk.as_ptr(), thunk_mem, thunk.len());
        libc::mprotect(thunk_mem as *mut libc::c_void, 4096, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC);

        let aligned_start = target_site & !4095;
        let aligned_len = (target_site + 6 - aligned_start).next_multiple_of(4096);
        if libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) == 0 {
            let target_mut = std::slice::from_raw_parts_mut(target_site as *mut u8, 6);
            let rel = (thunk_va as i64) - ((target_site + 5) as i64);
            target_mut[0] = 0xe9;
            target_mut[1..5].copy_from_slice(&(rel as i32).to_le_bytes());
            target_mut[5] = 0x90;
            libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_EXEC);
            tracing::info!(target_site = format_args!("{:#x}", target_site), thunk_va = format_args!("{:#x}", thunk_va), "patched epilogue zero-out null guard at 0x145520662");
        }
    }
}

unsafe fn patch_tls_null_guard(base: usize, info: &ImageInfo) {
    let target_rva = 0x4b5e;
    let target_site = base + target_rva;
    if target_rva + 18 >= info.size_of_image as usize {
        return;
    }
    let slice = unsafe { std::slice::from_raw_parts(target_site as *const u8, 18) };
    if slice != [
        0x48, 0x8b, 0x00,
        0x8b, 0xb8, 0x54, 0x14, 0x00, 0x00,
        0x83, 0xff, 0xff,
        0x0f, 0x84, 0x83, 0x00, 0x00, 0x00,
    ] {
        return;
    }

    let thunk_mem = match alloc_near(base, info.size_of_image as usize, 4096) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(error = %e, "failed to allocate thunk page for tls null guard");
            return;
        }
    };
    let thunk_va = thunk_mem as usize;

    let exit_site = base + 0x4bf3;

    let mut thunk = Vec::with_capacity(64);
    // test rax, rax
    thunk.extend_from_slice(&[0x48, 0x85, 0xc0]);
    // jz .Lnull
    let jz1 = thunk.len();
    thunk.extend_from_slice(&[0x74, 0x00]);
    // mov rax, [rax]
    thunk.extend_from_slice(&[0x48, 0x8b, 0x00]);
    // test rax, rax
    thunk.extend_from_slice(&[0x48, 0x85, 0xc0]);
    // jz .Lnull
    let jz2 = thunk.len();
    thunk.extend_from_slice(&[0x74, 0x00]);
    // mov edi, [rax + 0x1454]
    thunk.extend_from_slice(&[0x8b, 0xb8, 0x54, 0x14, 0x00, 0x00]);
    // cmp edi, -1
    thunk.extend_from_slice(&[0x83, 0xff, 0xff]);
    // je exit_site (0x140004bf3)
    let next_ip = thunk_va + thunk.len() + 6;
    let disp_exit = (exit_site as i64 - next_ip as i64) as i32;
    thunk.extend_from_slice(&[0x0f, 0x84]);
    thunk.extend_from_slice(&disp_exit.to_le_bytes());
    // jmp proceed_site (target_site + 18)
    let proceed_site = target_site + 18;
    let next_ip = thunk_va + thunk.len() + 5;
    let disp_proceed = (proceed_site as i64 - next_ip as i64) as i32;
    thunk.push(0xe9);
    thunk.extend_from_slice(&disp_proceed.to_le_bytes());

    // .Lnull:
    let lnull = thunk.len();
    thunk[jz1 + 1] = (lnull - (jz1 + 2)) as u8;
    thunk[jz2 + 1] = (lnull - (jz2 + 2)) as u8;
    // mov edi, -1
    thunk.extend_from_slice(&[0xbf, 0xff, 0xff, 0xff, 0xff]);
    // jmp exit_site
    let next_ip = thunk_va + thunk.len() + 5;
    let disp_exit2 = (exit_site as i64 - next_ip as i64) as i32;
    thunk.push(0xe9);
    thunk.extend_from_slice(&disp_exit2.to_le_bytes());

    #[cfg(unix)]
    unsafe {
        std::ptr::copy_nonoverlapping(thunk.as_ptr(), thunk_mem, thunk.len());
        libc::mprotect(thunk_mem as *mut libc::c_void, 4096, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC);

        let aligned_start = target_site & !4095;
        let aligned_len = (target_site + 18 - aligned_start).next_multiple_of(4096);
        if libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) == 0 {
            let target_mut = std::slice::from_raw_parts_mut(target_site as *mut u8, 18);
            let rel = (thunk_va as i64) - ((target_site + 5) as i64);
            target_mut[0] = 0xe9;
            target_mut[1..5].copy_from_slice(&(rel as i32).to_le_bytes());
            target_mut[5..18].fill(0x90);
            libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_EXEC);
            tracing::info!(target_site = format_args!("{:#x}", target_site), thunk_va = format_args!("{:#x}", thunk_va), "patched tls null guard at 0x140004b5e");
        }
    }
}

unsafe fn patch_shader_cleanup_trap(base: usize, info: &ImageInfo) {
    let target_rva = 0x375702f;
    let target_site = base + target_rva;
    if target_rva + 8 >= info.size_of_image as usize {
        return;
    }
    let slice = unsafe { std::slice::from_raw_parts(target_site as *const u8, 8) };
    if slice != [0xcc, 0x48, 0xc7, 0x06, 0x00, 0x00, 0x00, 0x00] {
        return;
    }
    #[cfg(unix)]
    unsafe {
        let aligned_start = target_site & !4095;
        let aligned_len = (target_site + 8 - aligned_start).next_multiple_of(4096);
        if libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) == 0 {
            let target_mut = std::slice::from_raw_parts_mut(target_site as *mut u8, 1);
            target_mut[0] = 0x90; // nop
            libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_EXEC);
            tracing::info!(target_site = format_args!("{:#x}", target_site), "patched shader cleanup trap int3 -> nop at 0x14375702f");
        }
    }
}

unsafe fn patch_worker_item_null_guard(base: usize, info: &ImageInfo) {
    let target_rva = 0x1f67809;
    let target_site = base + target_rva;
    let patch_len = 24;
    if target_rva + patch_len >= info.size_of_image as usize {
        return;
    }
    let expected = [
        0x44, 0x89, 0x73, 0x10,
        0x89, 0x7b, 0x14,
        0x89, 0x6b, 0x18,
        0x66, 0xc7, 0x43, 0x2e, 0x00, 0x00,
        0x48, 0x89, 0xf1,
        0xc5, 0xf8, 0x11, 0x43, 0x1e,
    ];
    let slice = unsafe { std::slice::from_raw_parts(target_site as *const u8, patch_len) };
    if slice != expected {
        return;
    }

    let thunk_mem = match alloc_near(base, info.size_of_image as usize, 4096) {
        Ok(p) => p,
        Err(_) => return,
    };
    let thunk_va = thunk_mem as usize;
    let target_continue = target_site + patch_len;

    let mut thunk = Vec::with_capacity(64);
    // 0x00: 48 85 db: test rbx, rbx
    thunk.extend_from_slice(&[0x48, 0x85, 0xdb]);
    // 0x03: 74 15: jz +0x15 (.Lskip at 0x1a)
    thunk.extend_from_slice(&[0x74, 0x15]);
    // 0x05: 44 89 73 10: mov [rbx + 0x10], r14d
    thunk.extend_from_slice(&[0x44, 0x89, 0x73, 0x10]);
    // 0x09: 89 7b 14: mov [rbx + 0x14], edi
    thunk.extend_from_slice(&[0x89, 0x7b, 0x14]);
    // 0x0c: 89 6b 18: mov [rbx + 0x18], ebp
    thunk.extend_from_slice(&[0x89, 0x6b, 0x18]);
    // 0x0f: 66 c7 43 2e 00 00: mov word ptr [rbx + 0x2e], 0
    thunk.extend_from_slice(&[0x66, 0xc7, 0x43, 0x2e, 0x00, 0x00]);
    // 0x15: c5 f8 11 43 1e: vmovups [rbx + 0x1e], xmm0
    thunk.extend_from_slice(&[0xc5, 0xf8, 0x11, 0x43, 0x1e]);
    // 0x1a: .Lskip:
    // 48 89 f1: mov rcx, rsi
    thunk.extend_from_slice(&[0x48, 0x89, 0xf1]);
    // jmp target_continue
    let next_ip = thunk_va + thunk.len() + 5;
    let disp = (target_continue as i64 - next_ip as i64) as i32;
    thunk.push(0xe9);
    thunk.extend_from_slice(&disp.to_le_bytes());

    #[cfg(unix)]
    unsafe {
        std::ptr::copy_nonoverlapping(thunk.as_ptr(), thunk_mem, thunk.len());
        libc::mprotect(thunk_mem as *mut libc::c_void, 4096, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC);
        let aligned_start = target_site & !4095;
        let aligned_len = (target_site + patch_len - aligned_start).next_multiple_of(4096);
        if libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) == 0 {
            let target_mut = std::slice::from_raw_parts_mut(target_site as *mut u8, patch_len);
            let disp = (thunk_va as i64 - (target_site as i64 + 5)) as i32;
            target_mut[0] = 0xe9;
            target_mut[1..5].copy_from_slice(&disp.to_le_bytes());
            target_mut[5..patch_len].fill(0x90);
            libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_EXEC);
            tracing::info!(target_site = format_args!("{:#x}", target_site), thunk_va = format_args!("{:#x}", thunk_va), "patched worker item null guard at 0x141f67809");
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "win64" fn victory_alloc_fallback_ring() -> *mut u8 {
    let p = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            0x20_0000,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_ANON | libc::MAP_PRIVATE,
            -1,
            0,
        )
    };
    if p != libc::MAP_FAILED {
        p as *mut u8
    } else {
        std::ptr::null_mut()
    }
}

unsafe fn patch_resource_pool_null_guard(base: usize, info: &ImageInfo) {
    let target_rva = 0x3e1a9f5;
    let target_site = base + target_rva;
    let patch_len = 13;
    if target_rva + patch_len >= info.size_of_image as usize {
        return;
    }
    let expected = [
        0x4c, 0x8b, 0x0d, 0xdc, 0x97, 0xaa, 0x05,
        0x49, 0x8b, 0x41, 0x10,
        0x89, 0xc1,
    ];
    let slice = unsafe { std::slice::from_raw_parts(target_site as *const u8, patch_len) };
    if slice != expected {
        return;
    }

    let thunk_mem = match alloc_near(base, info.size_of_image as usize, 65536) {
        Ok(p) => p,
        Err(_) => return,
    };
    let thunk_va = thunk_mem as usize;
    let target_continue = target_site + patch_len;
    let global_va = base + 0x98c41d8;
    let dummy_pool_va = thunk_va + 0x80;

    #[cfg(unix)]
    unsafe {
        std::ptr::write_bytes(thunk_mem, 0, 65536);
        let dummy_ptr = thunk_mem.add(0x80);
        (dummy_ptr as *mut usize).write(dummy_pool_va + 0x100);
        (dummy_ptr.add(0x08) as *mut usize).write(dummy_pool_va + 0x1000);
        (dummy_ptr.add(0x10) as *mut u64).write(0);
        (dummy_ptr.add(0x18) as *mut u64).write(64);
    }

    let mut thunk = Vec::with_capacity(64);
    // mov r11, global_va
    thunk.extend_from_slice(&[0x49, 0xbb]);
    thunk.extend_from_slice(&(global_va as u64).to_le_bytes());
    // mov r9, [r11]
    thunk.extend_from_slice(&[0x4d, 0x8b, 0x0b]);
    // test r9, r9
    thunk.extend_from_slice(&[0x4d, 0x85, 0xc9]);
    // jnz +10
    thunk.extend_from_slice(&[0x75, 0x0a]);
    // mov r9, dummy_pool_va
    thunk.extend_from_slice(&[0x49, 0xb9]);
    thunk.extend_from_slice(&(dummy_pool_va as u64).to_le_bytes());
    // mov rax, [r9 + 0x10]
    thunk.extend_from_slice(&[0x49, 0x8b, 0x41, 0x10]);
    // mov ecx, eax
    thunk.extend_from_slice(&[0x89, 0xc1]);
    // jmp target_continue
    let next_ip = thunk_va + thunk.len() + 5;
    let disp = (target_continue as i64 - next_ip as i64) as i32;
    thunk.push(0xe9);
    thunk.extend_from_slice(&disp.to_le_bytes());

    #[cfg(unix)]
    unsafe {
        std::ptr::copy_nonoverlapping(thunk.as_ptr(), thunk_mem, thunk.len());
        libc::mprotect(thunk_mem as *mut libc::c_void, 65536, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC);
        let aligned_start = target_site & !4095;
        let aligned_len = (target_site + patch_len - aligned_start).next_multiple_of(4096);
        if libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) == 0 {
            let target_mut = std::slice::from_raw_parts_mut(target_site as *mut u8, patch_len);
            let disp = (thunk_va as i64 - (target_site as i64 + 5)) as i32;
            target_mut[0] = 0xe9;
            target_mut[1..5].copy_from_slice(&disp.to_le_bytes());
            target_mut[5..patch_len].fill(0x90);
            libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_EXEC);
            tracing::info!(target_site = format_args!("{:#x}", target_site), thunk_va = format_args!("{:#x}", thunk_va), "patched resource pool null guard at 0x143e1a9f5");
        }
    }
}

unsafe fn patch_ring_alloc_null_guard(base: usize, info: &ImageInfo) {
    let target_rva = 0x47adc68;
    let target_site = base + target_rva;
    let patch_len = 15;
    if target_rva + patch_len >= info.size_of_image as usize {
        return;
    }
    // Expected:
    // 74 0c: je +0x0c -> 0x1447adc76 (int3)
    // 48 8d 0d 67 0d 6a 05: lea rcx, [rip + 0x56a0d67]
    // 4c 89 f2: mov rdx, r14
    // eb 0a: jmp +0x0a -> 0x1447adc80
    // cc: int3
    let expected = [
        0x74, 0x0c,
        0x48, 0x8d, 0x0d, 0x67, 0x0d, 0x6a, 0x05,
        0x4c, 0x89, 0xf2,
        0xeb, 0x0a,
        0xcc,
    ];
    let slice = unsafe { std::slice::from_raw_parts(target_site as *const u8, patch_len) };
    if slice != expected {
        return;
    }

    let thunk_mem = match alloc_near(base, info.size_of_image as usize, 4096) {
        Ok(p) => p,
        Err(_) => return,
    };
    let thunk_va = thunk_mem as usize;
    let helper_fn = victory_alloc_fallback_ring as *const () as usize;
    let target_continue = base + 0x47adc80;

    let mut thunk = Vec::with_capacity(64);
    // test r14, r14
    thunk.extend_from_slice(&[0x4d, 0x85, 0xf6]);
    // jnz .Lhas_r14 (placeholder)
    let jnz_has_r14 = thunk.len();
    thunk.extend_from_slice(&[0x75, 0x00]);
    // push rdi
    thunk.push(0x57);
    // push rsi
    thunk.push(0x56);
    // sub rsp, 8
    thunk.extend_from_slice(&[0x48, 0x83, 0xec, 0x08]);
    // mov r11, helper_fn
    thunk.extend_from_slice(&[0x49, 0xbb]);
    thunk.extend_from_slice(&(helper_fn as u64).to_le_bytes());
    // call r11
    thunk.extend_from_slice(&[0x41, 0xff, 0xd3]);
    // add rsp, 8
    thunk.extend_from_slice(&[0x48, 0x83, 0xc4, 0x08]);
    // pop rsi
    thunk.push(0x5e);
    // pop rdi
    thunk.push(0x5f);
    // mov r14, rax
    thunk.extend_from_slice(&[0x49, 0x89, 0xc6]);
    // .Lhas_r14:
    let has_r14_off = thunk.len();
    thunk[jnz_has_r14 + 1] = (has_r14_off - (jnz_has_r14 + 2)) as u8;
    // lea rcx, [rip_calc] -> 0x149e4e9d8
    let rip_disp = (base + 0x9e4e9d8) as i64;
    thunk.extend_from_slice(&[0x48, 0xb9]);
    thunk.extend_from_slice(&(rip_disp as u64).to_le_bytes());
    // mov rdx, r14
    thunk.extend_from_slice(&[0x4c, 0x89, 0xf2]);
    // jmp target_continue (0x1447adc80)
    let next_ip = thunk_va + thunk.len() + 5;
    let disp = (target_continue as i64 - next_ip as i64) as i32;
    thunk.push(0xe9);
    thunk.extend_from_slice(&disp.to_le_bytes());

    #[cfg(unix)]
    unsafe {
        std::ptr::copy_nonoverlapping(thunk.as_ptr(), thunk_mem, thunk.len());
        libc::mprotect(thunk_mem as *mut libc::c_void, 4096, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC);
        let aligned_start = target_site & !4095;
        let aligned_len = (target_site + patch_len - aligned_start).next_multiple_of(4096);
        if libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) == 0 {
            let target_mut = std::slice::from_raw_parts_mut(target_site as *mut u8, patch_len);
            let disp = (thunk_va as i64 - (target_site as i64 + 5)) as i32;
            target_mut[0] = 0xe9;
            target_mut[1..5].copy_from_slice(&disp.to_le_bytes());
            target_mut[5..patch_len].fill(0x90);
            libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_EXEC);
            tracing::info!(target_site = format_args!("{:#x}", target_site), thunk_va = format_args!("{:#x}", thunk_va), "patched ring alloc null guard at 0x1447adc68");
        }
    }
}

unsafe fn patch_ring_buffer_null_guard(base: usize, info: &ImageInfo) {
    let target_rva = 0x4f39000;
    let target_site = base + target_rva;
    let patch_len = 10;
    if target_rva + patch_len >= info.size_of_image as usize {
        return;
    }
    let expected = [
        0x4a, 0x8d, 0x04, 0x02,
        0x48, 0x89, 0x11,
        0x4d, 0x89, 0xc1,
    ];
    let slice = unsafe { std::slice::from_raw_parts(target_site as *const u8, patch_len) };
    if slice != expected {
        return;
    }

    let thunk_mem = match alloc_near(base, info.size_of_image as usize, 4096) {
        Ok(p) => p,
        Err(_) => return,
    };
    let thunk_va = thunk_mem as usize;
    let target_continue = target_site + patch_len;
    let helper_fn = victory_alloc_fallback_ring as *const () as usize;

    let mut thunk = Vec::with_capacity(112);
    // Validate rcx:
    // mov r11, rcx
    thunk.extend_from_slice(&[0x49, 0x89, 0xcb]);
    // shr r11, 32
    thunk.extend_from_slice(&[0x49, 0xc1, 0xeb, 0x20]);
    // dec r11
    thunk.extend_from_slice(&[0x49, 0xff, 0xcb]);
    // cmp r11, 0x7fff
    thunk.extend_from_slice(&[0x49, 0x81, 0xfb, 0xff, 0x7f, 0x00, 0x00]);
    // ja .Lret_zero (placeholder)
    let ja_zero_idx = thunk.len();
    thunk.extend_from_slice(&[0x77, 0x00]);
    // test cl, 7
    thunk.extend_from_slice(&[0xf6, 0xc1, 0x07]);
    // jnz .Lret_zero (placeholder)
    let jnz_zero_idx = thunk.len();
    thunk.extend_from_slice(&[0x75, 0x00]);

    // Validate rdx:
    // mov r11, rdx
    thunk.extend_from_slice(&[0x49, 0x89, 0xd3]);
    // shr r11, 32
    thunk.extend_from_slice(&[0x49, 0xc1, 0xeb, 0x20]);
    // dec r11
    thunk.extend_from_slice(&[0x49, 0xff, 0xcb]);
    // cmp r11, 0x7fff
    thunk.extend_from_slice(&[0x49, 0x81, 0xfb, 0xff, 0x7f, 0x00, 0x00]);
    // ja .Lalloc_fallback (placeholder)
    let ja_alloc_idx = thunk.len();
    thunk.extend_from_slice(&[0x77, 0x00]);
    // test dl, 7
    thunk.extend_from_slice(&[0xf6, 0xc2, 0x07]);
    // jz .Lexecute_original (placeholder)
    let jz_orig_idx = thunk.len();
    thunk.extend_from_slice(&[0x74, 0x00]);

    // .Lalloc_fallback:
    let alloc_offset = thunk.len();
    thunk[ja_alloc_idx + 1] = (alloc_offset - (ja_alloc_idx + 2)) as u8;

    // push rdi
    thunk.push(0x57);
    // push rsi
    thunk.push(0x56);
    // push rcx
    thunk.push(0x51);
    // push r8
    thunk.extend_from_slice(&[0x41, 0x50]);
    // sub rsp, 8
    thunk.extend_from_slice(&[0x48, 0x83, 0xec, 0x08]);
    // mov r11, helper_fn
    thunk.extend_from_slice(&[0x49, 0xbb]);
    thunk.extend_from_slice(&(helper_fn as u64).to_le_bytes());
    // call r11
    thunk.extend_from_slice(&[0x41, 0xff, 0xd3]);
    // add rsp, 8
    thunk.extend_from_slice(&[0x48, 0x83, 0xc4, 0x08]);
    // pop r8
    thunk.extend_from_slice(&[0x41, 0x58]);
    // pop rcx
    thunk.push(0x59);
    // pop rsi
    thunk.push(0x5e);
    // pop rdi
    thunk.push(0x5f);
    // mov rdx, rax
    thunk.extend_from_slice(&[0x48, 0x89, 0xc2]);

    // .Lexecute_original:
    let orig_offset = thunk.len();
    thunk[jz_orig_idx + 1] = (orig_offset - (jz_orig_idx + 2)) as u8;

    // lea rax, [rdx + r8]
    thunk.extend_from_slice(&[0x4a, 0x8d, 0x04, 0x02]);
    // mov [rcx], rdx
    thunk.extend_from_slice(&[0x48, 0x89, 0x11]);
    // mov r9, r8
    thunk.extend_from_slice(&[0x4d, 0x89, 0xc1]);
    // jmp target_continue (0x144f3900a)
    let next_ip = thunk_va + thunk.len() + 5;
    let disp = (target_continue as i64 - next_ip as i64) as i32;
    thunk.push(0xe9);
    thunk.extend_from_slice(&disp.to_le_bytes());

    // .Lret_zero:
    let zero_offset = thunk.len();
    thunk[ja_zero_idx + 1] = (zero_offset - (ja_zero_idx + 2)) as u8;
    thunk[jnz_zero_idx + 1] = (zero_offset - (jnz_zero_idx + 2)) as u8;

    // xor eax, eax
    thunk.extend_from_slice(&[0x31, 0xc0]);
    // ret
    thunk.push(0xc3);

    #[cfg(unix)]
    unsafe {
        std::ptr::copy_nonoverlapping(thunk.as_ptr(), thunk_mem, thunk.len());
        libc::mprotect(thunk_mem as *mut libc::c_void, 4096, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC);
        let aligned_start = target_site & !4095;
        let aligned_len = (target_site + patch_len - aligned_start).next_multiple_of(4096);
        if libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) == 0 {
            let target_mut = std::slice::from_raw_parts_mut(target_site as *mut u8, patch_len);
            let disp = (thunk_va as i64 - (target_site as i64 + 5)) as i32;
            target_mut[0] = 0xe9;
            target_mut[1..5].copy_from_slice(&disp.to_le_bytes());
            target_mut[5..patch_len].fill(0x90);
            libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_EXEC);
            tracing::info!(target_site = format_args!("{:#x}", target_site), thunk_va = format_args!("{:#x}", thunk_va), "patched ring buffer null guard at 0x144f39000");
        }
    }
}

unsafe fn patch_sentinel_store_null_guard(base: usize, info: &ImageInfo) {
    let target_rva = 0x4791883;
    let target_site = base + target_rva;
    let patch_len = 7;
    if target_rva + patch_len >= info.size_of_image as usize {
        return;
    }
    let expected = [0x66, 0x41, 0xc7, 0x01, 0xff, 0xff, 0xc3];
    let slice = unsafe { std::slice::from_raw_parts(target_site as *const u8, patch_len) };
    if slice != expected {
        return;
    }

    let thunk_mem = match alloc_near(base, info.size_of_image as usize, 4096) {
        Ok(p) => p,
        Err(_) => return,
    };
    let thunk_va = thunk_mem as usize;

    let mut thunk = Vec::with_capacity(32);
    // test r9, r9
    thunk.extend_from_slice(&[0x4d, 0x85, 0xc9]);
    // jz +6
    thunk.extend_from_slice(&[0x74, 0x06]);
    // mov word ptr [r9], 0xffff
    thunk.extend_from_slice(&[0x66, 0x41, 0xc7, 0x01, 0xff, 0xff]);
    // ret
    thunk.push(0xc3);

    #[cfg(unix)]
    unsafe {
        std::ptr::copy_nonoverlapping(thunk.as_ptr(), thunk_mem, thunk.len());
        libc::mprotect(thunk_mem as *mut libc::c_void, 4096, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC);
        let aligned_start = target_site & !4095;
        let aligned_len = (target_site + patch_len - aligned_start).next_multiple_of(4096);
        if libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) == 0 {
            let target_mut = std::slice::from_raw_parts_mut(target_site as *mut u8, patch_len);
            let disp = (thunk_va as i64 - (target_site as i64 + 5)) as i32;
            target_mut[0] = 0xe9;
            target_mut[1..5].copy_from_slice(&disp.to_le_bytes());
            target_mut[5..patch_len].fill(0x90);
            libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_EXEC);
            tracing::info!(target_site = format_args!("{:#x}", target_site), thunk_va = format_args!("{:#x}", thunk_va), "patched sentinel store null guard at 0x144791883");
        }
    }
}

unsafe fn patch_tls_array_null_guard(base: usize, info: &ImageInfo) {
    let target_rva = 0x3ac6;
    let target_site = base + target_rva;
    let patch_len = 12;
    if target_rva + patch_len >= info.size_of_image as usize {
        return;
    }
    let expected = [
        0x65, 0x48, 0x8b, 0x14, 0x25, 0x20, 0x08, 0x00, 0x00,
        0x48, 0x89, 0xce,
    ];
    let slice = unsafe { std::slice::from_raw_parts(target_site as *const u8, patch_len) };
    if slice != expected {
        return;
    }

    let thunk_mem = match alloc_near(base, info.size_of_image as usize, 4096) {
        Ok(p) => p,
        Err(_) => return,
    };
    let thunk_va = thunk_mem as usize;
    let target_continue = target_site + patch_len;
    let helper_fn = crate::tls::victory_ensure_thread_teb as *const () as usize;

    let mut thunk = Vec::with_capacity(64);
    // mov rdx, gs:[0x820]
    thunk.extend_from_slice(&[0x65, 0x48, 0x8b, 0x14, 0x25, 0x20, 0x08, 0x00, 0x00]);
    // mov rsi, rcx
    thunk.extend_from_slice(&[0x48, 0x89, 0xce]);
    // test rdx, rdx
    thunk.extend_from_slice(&[0x48, 0x85, 0xd2]);
    // jnz +0x1e
    thunk.extend_from_slice(&[0x75, 0x1e]);
    // sub rsp, 8
    thunk.extend_from_slice(&[0x48, 0x83, 0xec, 0x08]);
    // mov r11, helper_fn
    thunk.extend_from_slice(&[0x49, 0xbb]);
    thunk.extend_from_slice(&(helper_fn as u64).to_le_bytes());
    // call r11
    thunk.extend_from_slice(&[0x41, 0xff, 0xd3]);
    // add rsp, 8
    thunk.extend_from_slice(&[0x48, 0x83, 0xc4, 0x08]);
    // mov rdx, gs:[0x820]
    thunk.extend_from_slice(&[0x65, 0x48, 0x8b, 0x14, 0x25, 0x20, 0x08, 0x00, 0x00]);
    // jmp target_continue
    let next_ip = thunk_va + thunk.len() + 5;
    let disp = (target_continue as i64 - next_ip as i64) as i32;
    thunk.push(0xe9);
    thunk.extend_from_slice(&disp.to_le_bytes());

    #[cfg(unix)]
    unsafe {
        std::ptr::copy_nonoverlapping(thunk.as_ptr(), thunk_mem, thunk.len());
        libc::mprotect(thunk_mem as *mut libc::c_void, 4096, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC);
        let aligned_start = target_site & !4095;
        let aligned_len = (target_site + patch_len - aligned_start).next_multiple_of(4096);
        if libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) == 0 {
            let target_mut = std::slice::from_raw_parts_mut(target_site as *mut u8, patch_len);
            let disp = (thunk_va as i64 - (target_site as i64 + 5)) as i32;
            target_mut[0] = 0xe9;
            target_mut[1..5].copy_from_slice(&disp.to_le_bytes());
            target_mut[5..patch_len].fill(0x90);
            libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_EXEC);
            tracing::info!(target_site = format_args!("{:#x}", target_site), thunk_va = format_args!("{:#x}", thunk_va), "patched tls array null guard at 0x140003ac6");
        }
    }
}

unsafe fn patch_tls_store_null_guard(base: usize, info: &ImageInfo) {
    let target_rva = 0x4c01;
    let target_site = base + target_rva;
    let patch_len = 8;
    if target_rva + patch_len >= info.size_of_image as usize {
        return;
    }
    let expected = [0x41, 0x89, 0x06, 0xe9, 0x67, 0xff, 0xff, 0xff];
    let slice = unsafe { std::slice::from_raw_parts(target_site as *const u8, patch_len) };
    if slice != expected {
        return;
    }

    let thunk_mem = match alloc_near(base, info.size_of_image as usize, 4096) {
        Ok(p) => p,
        Err(_) => return,
    };
    let thunk_va = thunk_mem as usize;
    let target_continue = base + 0x4b70;

    let mut thunk = Vec::with_capacity(32);
    // cmp r14, 0x10000
    thunk.extend_from_slice(&[0x49, 0x81, 0xfe, 0x00, 0x00, 0x01, 0x00]);
    // jb +0x03
    thunk.extend_from_slice(&[0x72, 0x03]);
    // mov [r14], eax
    thunk.extend_from_slice(&[0x41, 0x89, 0x06]);
    // jmp 0x140004b70
    let next_ip = thunk_va + thunk.len() + 5;
    let disp = (target_continue as i64 - next_ip as i64) as i32;
    thunk.push(0xe9);
    thunk.extend_from_slice(&disp.to_le_bytes());

    #[cfg(unix)]
    unsafe {
        std::ptr::copy_nonoverlapping(thunk.as_ptr(), thunk_mem, thunk.len());
        libc::mprotect(thunk_mem as *mut libc::c_void, 4096, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC);
        let aligned_start = target_site & !4095;
        let aligned_len = (target_site + patch_len - aligned_start).next_multiple_of(4096);
        if libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) == 0 {
            let target_mut = std::slice::from_raw_parts_mut(target_site as *mut u8, patch_len);
            let disp = (thunk_va as i64 - (target_site as i64 + 5)) as i32;
            target_mut[0] = 0xe9;
            target_mut[1..5].copy_from_slice(&disp.to_le_bytes());
            target_mut[5..patch_len].fill(0x90);
            libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_EXEC);
            tracing::info!(target_site = format_args!("{:#x}", target_site), thunk_va = format_args!("{:#x}", thunk_va), "patched tls store null guard at 0x140004c01");
        }
    }
}

unsafe fn patch_task_table_null_guard(base: usize, info: &ImageInfo) {
    let target_rva = 0x1da77d8;
    let target_site = base + target_rva;
    let patch_len = 15;
    if target_rva + patch_len >= info.size_of_image as usize {
        return;
    }
    let expected = [
        0x44, 0x8b, 0x70, 0x0c,
        0x42, 0x8d, 0x04, 0xf5, 0x00, 0x00, 0x00, 0x00,
        0x8d, 0x14, 0x40,
    ];
    let slice = unsafe { std::slice::from_raw_parts(target_site as *const u8, patch_len) };
    if slice != expected {
        return;
    }

    let thunk_mem = match alloc_near(base, info.size_of_image as usize, 4096) {
        Ok(p) => p,
        Err(_) => return,
    };
    let thunk_va = thunk_mem as usize;
    let target_continue = target_site + patch_len;

    let mut thunk = Vec::with_capacity(48);
    // test rax, rax
    thunk.extend_from_slice(&[0x48, 0x85, 0xc0]);
    // jnz +0x12 -> .Lhas_rax
    thunk.extend_from_slice(&[0x75, 0x12]);
    // mov r14d, 1
    thunk.extend_from_slice(&[0x41, 0xbe, 0x01, 0x00, 0x00, 0x00]);
    // mov eax, 8
    thunk.extend_from_slice(&[0xb8, 0x08, 0x00, 0x00, 0x00]);
    // mov edx, 24
    thunk.extend_from_slice(&[0xba, 0x18, 0x00, 0x00, 0x00]);
    // jmp +0x0f -> target_continue
    thunk.extend_from_slice(&[0xeb, 0x0f]);
    // .Lhas_rax:
    // mov r14d, [rax + 0xc]
    thunk.extend_from_slice(&[0x44, 0x8b, 0x70, 0x0c]);
    // lea eax, [r14 * 8]
    thunk.extend_from_slice(&[0x42, 0x8d, 0x04, 0xf5, 0x00, 0x00, 0x00, 0x00]);
    // lea edx, [rax + rax * 2]
    thunk.extend_from_slice(&[0x8d, 0x14, 0x40]);
    // jmp target_continue
    let next_ip = thunk_va + thunk.len() + 5;
    let disp = (target_continue as i64 - next_ip as i64) as i32;
    thunk.push(0xe9);
    thunk.extend_from_slice(&disp.to_le_bytes());

    #[cfg(unix)]
    unsafe {
        std::ptr::copy_nonoverlapping(thunk.as_ptr(), thunk_mem, thunk.len());
        libc::mprotect(thunk_mem as *mut libc::c_void, 4096, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC);
        let aligned_start = target_site & !4095;
        let aligned_len = (target_site + patch_len - aligned_start).next_multiple_of(4096);
        if libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) == 0 {
            let target_mut = std::slice::from_raw_parts_mut(target_site as *mut u8, patch_len);
            let disp = (thunk_va as i64 - (target_site as i64 + 5)) as i32;
            target_mut[0] = 0xe9;
            target_mut[1..5].copy_from_slice(&disp.to_le_bytes());
            target_mut[5..patch_len].fill(0x90);
            libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_EXEC);
            tracing::info!(target_site = format_args!("{:#x}", target_site), thunk_va = format_args!("{:#x}", thunk_va), "patched task table null guard at 0x141da77d8");
        }
    }
}

unsafe fn patch_second_task_table_null_guard(base: usize, info: &ImageInfo) {
    let target_rva = 0x1da7975;
    let target_site = base + target_rva;
    let patch_len = 13;
    if target_rva + patch_len >= info.size_of_image as usize {
        return;
    }
    // Expected:
    // 8b 58 0c: mov ebx, [rax + 0xc]
    // 8d 04 dd 00 00 00 00: lea eax, [rbx * 8]
    // 8d 14 40: lea edx, [rax + rax * 2]
    let expected = [
        0x8b, 0x58, 0x0c,
        0x8d, 0x04, 0xdd, 0x00, 0x00, 0x00, 0x00,
        0x8d, 0x14, 0x40,
    ];
    let slice = unsafe { std::slice::from_raw_parts(target_site as *const u8, patch_len) };
    if slice != expected {
        return;
    }

    let thunk_mem = match alloc_near(base, info.size_of_image as usize, 4096) {
        Ok(p) => p,
        Err(_) => return,
    };
    let thunk_va = thunk_mem as usize;
    let target_continue = target_site + patch_len;

    let mut thunk = Vec::with_capacity(48);
    // test rax, rax
    thunk.extend_from_slice(&[0x48, 0x85, 0xc0]);
    // jnz +0x11 -> .Lhas_rax
    thunk.extend_from_slice(&[0x75, 0x11]);
    // mov ebx, 1
    thunk.extend_from_slice(&[0xbb, 0x01, 0x00, 0x00, 0x00]);
    // mov eax, 8
    thunk.extend_from_slice(&[0xb8, 0x08, 0x00, 0x00, 0x00]);
    // mov edx, 24
    thunk.extend_from_slice(&[0xba, 0x18, 0x00, 0x00, 0x00]);
    // jmp +0x0d -> target_continue
    thunk.extend_from_slice(&[0xeb, 0x0d]);
    // .Lhas_rax:
    // mov ebx, [rax + 0xc]
    thunk.extend_from_slice(&[0x8b, 0x58, 0x0c]);
    // lea eax, [rbx * 8]
    thunk.extend_from_slice(&[0x8d, 0x04, 0xdd, 0x00, 0x00, 0x00, 0x00]);
    // lea edx, [rax + rax * 2]
    thunk.extend_from_slice(&[0x8d, 0x14, 0x40]);
    // jmp target_continue
    let next_ip = thunk_va + thunk.len() + 5;
    let disp = (target_continue as i64 - next_ip as i64) as i32;
    thunk.push(0xe9);
    thunk.extend_from_slice(&disp.to_le_bytes());

    #[cfg(unix)]
    unsafe {
        std::ptr::copy_nonoverlapping(thunk.as_ptr(), thunk_mem, thunk.len());
        libc::mprotect(thunk_mem as *mut libc::c_void, 4096, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC);
        let aligned_start = target_site & !4095;
        let aligned_len = (target_site + patch_len - aligned_start).next_multiple_of(4096);
        if libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) == 0 {
            let target_mut = std::slice::from_raw_parts_mut(target_site as *mut u8, patch_len);
            let disp = (thunk_va as i64 - (target_site as i64 + 5)) as i32;
            target_mut[0] = 0xe9;
            target_mut[1..5].copy_from_slice(&disp.to_le_bytes());
            target_mut[5..patch_len].fill(0x90);
            libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_EXEC);
            tracing::info!(target_site = format_args!("{:#x}", target_site), thunk_va = format_args!("{:#x}", thunk_va), "patched second task table null guard at 0x141da7975");
        }
    }
}

unsafe fn patch_scheduler_loop_guard(base: usize, info: &ImageInfo) {
    let target_rva = 0x4dac762;
    let target_site = base + target_rva;
    let patch_len = 9;
    if target_rva + 0x4d >= info.size_of_image as usize {
        return;
    }
    let expected = [
        0x4c, 0x8d, 0x7f, 0x68,
        0x4d, 0x39, 0xfe,
        0x74, 0x44,
    ];
    let slice = unsafe { std::slice::from_raw_parts(target_site as *const u8, patch_len) };
    if slice != expected {
        return;
    }

    let thunk_mem = match alloc_near(base, info.size_of_image as usize, 4096) {
        Ok(p) => p,
        Err(_) => return,
    };
    let thunk_va = thunk_mem as usize;
    let target_continue = target_site + patch_len; // 0x144dac76b
    let loop_exit = base + 0x4dac7af;             // 0x144dac7af

    let mut thunk = Vec::with_capacity(64);
    // lea r15, [rdi + 0x68]
    thunk.extend_from_slice(&[0x4c, 0x8d, 0x7f, 0x68]);
    // cmp r14, r15
    thunk.extend_from_slice(&[0x4d, 0x39, 0xfe]);
    // je .Lexit (placeholder)
    let je_exit = thunk.len();
    thunk.extend_from_slice(&[0x74, 0x00]);

    // mov r11, r14
    thunk.extend_from_slice(&[0x4d, 0x89, 0xf3]);
    // shr r11, 32
    thunk.extend_from_slice(&[0x49, 0xc1, 0xeb, 0x20]);
    // dec r11
    thunk.extend_from_slice(&[0x49, 0xff, 0xcb]);
    // cmp r11, 0x7fff
    thunk.extend_from_slice(&[0x49, 0x81, 0xfb, 0xff, 0x7f, 0x00, 0x00]);
    // ja .Lexit (placeholder)
    let ja_exit = thunk.len();
    thunk.extend_from_slice(&[0x77, 0x00]);

    // test r14b, 7
    thunk.extend_from_slice(&[0x41, 0xf6, 0xc6, 0x07]);
    // jnz .Lexit (placeholder)
    let jnz_exit = thunk.len();
    thunk.extend_from_slice(&[0x75, 0x00]);

    // jmp target_continue (0x144dac76b)
    let next_ip = thunk_va + thunk.len() + 5;
    let disp = (target_continue as i64 - next_ip as i64) as i32;
    thunk.push(0xe9);
    thunk.extend_from_slice(&disp.to_le_bytes());

    // .Lexit:
    let exit_off = thunk.len();
    thunk[je_exit + 1] = (exit_off - (je_exit + 2)) as u8;
    thunk[ja_exit + 1] = (exit_off - (ja_exit + 2)) as u8;
    thunk[jnz_exit + 1] = (exit_off - (jnz_exit + 2)) as u8;

    // jmp loop_exit (0x144dac7af)
    let next_ip2 = thunk_va + thunk.len() + 5;
    let disp2 = (loop_exit as i64 - next_ip2 as i64) as i32;
    thunk.push(0xe9);
    thunk.extend_from_slice(&disp2.to_le_bytes());

    #[cfg(unix)]
    unsafe {
        std::ptr::copy_nonoverlapping(thunk.as_ptr(), thunk_mem, thunk.len());
        libc::mprotect(thunk_mem as *mut libc::c_void, 4096, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC);
        let aligned_start = target_site & !4095;
        let aligned_len = (target_site + 0x4f - aligned_start).next_multiple_of(4096);
        if libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) == 0 {
            let target_mut = std::slice::from_raw_parts_mut(target_site as *mut u8, patch_len);
            let disp = (thunk_va as i64 - (target_site as i64 + 5)) as i32;
            target_mut[0] = 0xe9;
            target_mut[1..5].copy_from_slice(&disp.to_le_bytes());
            target_mut[5..patch_len].fill(0x90);

            // Also redirect backward loop jump at target_site + 0x4b (0x144dac7ad):
            let loop_back_site = target_site + 0x4b;
            let loop_back_mut = std::slice::from_raw_parts_mut(loop_back_site as *mut u8, 2);
            if loop_back_mut == [0x75, 0xc0] {
                loop_back_mut[1] = 0xb3;
            }
            libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_EXEC);
            tracing::info!(target_site = format_args!("{:#x}", target_site), thunk_va = format_args!("{:#x}", thunk_va), "patched scheduler loop guard at 0x144dac762");
        }
    }
}

unsafe fn patch_scheduler_list_unlink_guard(base: usize, info: &ImageInfo) {
    let target_rva = 0x4dac783;
    let target_site = base + target_rva;
    let patch_len = 22;
    if target_rva + patch_len >= info.size_of_image as usize {
        return;
    }
    let expected = [
        0x4c, 0x89, 0x79, 0x10,
        0x48, 0x8b, 0x8f, 0x80, 0x00, 0x00, 0x00,
        0x4c, 0x89, 0xb7, 0x80, 0x00, 0x00, 0x00,
        0x4c, 0x89, 0x71, 0x10,
    ];
    let slice = unsafe { std::slice::from_raw_parts(target_site as *const u8, patch_len) };
    if slice != expected {
        return;
    }

    let thunk_mem = match alloc_near(base, info.size_of_image as usize, 4096) {
        Ok(p) => p,
        Err(_) => return,
    };
    let thunk_va = thunk_mem as usize;
    let target_continue = target_site + patch_len;

    let mut thunk = Vec::with_capacity(80);
    // mov r11, rcx
    thunk.extend_from_slice(&[0x49, 0x89, 0xcb]);
    // shr r11, 32
    thunk.extend_from_slice(&[0x49, 0xc1, 0xeb, 0x20]);
    // dec r11
    thunk.extend_from_slice(&[0x49, 0xff, 0xcb]);
    // cmp r11, 0x7fff
    thunk.extend_from_slice(&[0x49, 0x81, 0xfb, 0xff, 0x7f, 0x00, 0x00]);
    // ja .Lskip1 (placeholder)
    let ja_skip1 = thunk.len();
    thunk.extend_from_slice(&[0x77, 0x00]);
    // test cl, 7
    thunk.extend_from_slice(&[0xf6, 0xc1, 0x07]);
    // jnz .Lskip1 (placeholder)
    let jnz_skip1 = thunk.len();
    thunk.extend_from_slice(&[0x75, 0x00]);
    // mov [rcx + 0x10], r15
    thunk.extend_from_slice(&[0x4c, 0x89, 0x79, 0x10]);
    // .Lskip1:
    let skip1_off = thunk.len();
    thunk[ja_skip1 + 1] = (skip1_off - (ja_skip1 + 2)) as u8;
    thunk[jnz_skip1 + 1] = (skip1_off - (jnz_skip1 + 2)) as u8;

    // mov rcx, [rdi + 0x80]
    thunk.extend_from_slice(&[0x48, 0x8b, 0x8f, 0x80, 0x00, 0x00, 0x00]);
    // mov [rdi + 0x80], r14
    thunk.extend_from_slice(&[0x4c, 0x89, 0xb7, 0x80, 0x00, 0x00, 0x00]);

    // mov r11, rcx
    thunk.extend_from_slice(&[0x49, 0x89, 0xcb]);
    // shr r11, 32
    thunk.extend_from_slice(&[0x49, 0xc1, 0xeb, 0x20]);
    // dec r11
    thunk.extend_from_slice(&[0x49, 0xff, 0xcb]);
    // cmp r11, 0x7fff
    thunk.extend_from_slice(&[0x49, 0x81, 0xfb, 0xff, 0x7f, 0x00, 0x00]);
    // ja .Lskip2 (placeholder)
    let ja_skip2 = thunk.len();
    thunk.extend_from_slice(&[0x77, 0x00]);
    // test cl, 7
    thunk.extend_from_slice(&[0xf6, 0xc1, 0x07]);
    // jnz .Lskip2 (placeholder)
    let jnz_skip2 = thunk.len();
    thunk.extend_from_slice(&[0x75, 0x00]);
    // mov [rcx + 0x10], r14
    thunk.extend_from_slice(&[0x4c, 0x89, 0x71, 0x10]);
    // .Lskip2:
    let skip2_off = thunk.len();
    thunk[ja_skip2 + 1] = (skip2_off - (ja_skip2 + 2)) as u8;
    thunk[jnz_skip2 + 1] = (skip2_off - (jnz_skip2 + 2)) as u8;

    // jmp target_continue
    let next_ip = thunk_va + thunk.len() + 5;
    let disp = (target_continue as i64 - next_ip as i64) as i32;
    thunk.push(0xe9);
    thunk.extend_from_slice(&disp.to_le_bytes());

    #[cfg(unix)]
    unsafe {
        std::ptr::copy_nonoverlapping(thunk.as_ptr(), thunk_mem, thunk.len());
        libc::mprotect(thunk_mem as *mut libc::c_void, 4096, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC);
        let aligned_start = target_site & !4095;
        let aligned_len = (target_site + patch_len - aligned_start).next_multiple_of(4096);
        if libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) == 0 {
            let target_mut = std::slice::from_raw_parts_mut(target_site as *mut u8, patch_len);
            let disp = (thunk_va as i64 - (target_site as i64 + 5)) as i32;
            target_mut[0] = 0xe9;
            target_mut[1..5].copy_from_slice(&disp.to_le_bytes());
            target_mut[5..patch_len].fill(0x90);
            libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_EXEC);
            tracing::info!(target_site = format_args!("{:#x}", target_site), thunk_va = format_args!("{:#x}", thunk_va), "patched scheduler list unlink guard at 0x144dac783");
        }
    }
}

unsafe fn patch_scheduler_post_loop_guard(base: usize, info: &ImageInfo) {
    let target_rva = 0x4dac7ed;
    let target_site = base + target_rva;
    let patch_len = 12;
    if target_rva + patch_len >= info.size_of_image as usize {
        return;
    }
    let expected = [
        0x49, 0x89, 0x5e, 0x10,
        0x4c, 0x89, 0x7b, 0x10,
        0x4c, 0x89, 0x73, 0x08,
    ];
    let slice = unsafe { std::slice::from_raw_parts(target_site as *const u8, patch_len) };
    if slice != expected {
        return;
    }

    let thunk_mem = match alloc_near(base, info.size_of_image as usize, 4096) {
        Ok(p) => p,
        Err(_) => return,
    };
    let thunk_va = thunk_mem as usize;
    let target_continue = target_site + patch_len;

    let mut thunk = Vec::with_capacity(64);
    // mov r11, r14
    thunk.extend_from_slice(&[0x4d, 0x89, 0xf3]);
    // shr r11, 32
    thunk.extend_from_slice(&[0x49, 0xc1, 0xeb, 0x20]);
    // dec r11
    thunk.extend_from_slice(&[0x49, 0xff, 0xcb]);
    // cmp r11, 0x7fff
    thunk.extend_from_slice(&[0x49, 0x81, 0xfb, 0xff, 0x7f, 0x00, 0x00]);
    // ja .Lskip_link
    let ja_skip = thunk.len();
    thunk.extend_from_slice(&[0x77, 0x00]);
    // test r14b, 7
    thunk.extend_from_slice(&[0x41, 0xf6, 0xc6, 0x07]);
    // jnz .Lskip_link
    let jnz_skip = thunk.len();
    thunk.extend_from_slice(&[0x75, 0x00]);
    // mov [r14 + 0x10], rbx
    thunk.extend_from_slice(&[0x49, 0x89, 0x5e, 0x10]);

    // .Lskip_link:
    let skip_off = thunk.len();
    thunk[ja_skip + 1] = (skip_off - (ja_skip + 2)) as u8;
    thunk[jnz_skip + 1] = (skip_off - (jnz_skip + 2)) as u8;

    // mov [rbx + 0x10], r15
    thunk.extend_from_slice(&[0x4c, 0x89, 0x7b, 0x10]);

    // mov r11, r14
    thunk.extend_from_slice(&[0x4d, 0x89, 0xf3]);
    // shr r11, 32
    thunk.extend_from_slice(&[0x49, 0xc1, 0xeb, 0x20]);
    // dec r11
    thunk.extend_from_slice(&[0x49, 0xff, 0xcb]);
    // cmp r11, 0x7fff
    thunk.extend_from_slice(&[0x49, 0x81, 0xfb, 0xff, 0x7f, 0x00, 0x00]);
    // jbe +3
    thunk.extend_from_slice(&[0x76, 0x03]);
    // xor r14d, r14d
    thunk.extend_from_slice(&[0x45, 0x31, 0xf6]);
    // mov [rbx + 0x8], r14
    thunk.extend_from_slice(&[0x4c, 0x89, 0x73, 0x08]);

    // jmp target_continue (0x144dac7f9)
    let next_ip = thunk_va + thunk.len() + 5;
    let disp = (target_continue as i64 - next_ip as i64) as i32;
    thunk.push(0xe9);
    thunk.extend_from_slice(&disp.to_le_bytes());

    #[cfg(unix)]
    unsafe {
        std::ptr::copy_nonoverlapping(thunk.as_ptr(), thunk_mem, thunk.len());
        libc::mprotect(thunk_mem as *mut libc::c_void, 4096, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC);
        let aligned_start = target_site & !4095;
        let aligned_len = (target_site + patch_len - aligned_start).next_multiple_of(4096);
        if libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) == 0 {
            let target_mut = std::slice::from_raw_parts_mut(target_site as *mut u8, patch_len);
            let disp = (thunk_va as i64 - (target_site as i64 + 5)) as i32;
            target_mut[0] = 0xe9;
            target_mut[1..5].copy_from_slice(&disp.to_le_bytes());
            target_mut[5..patch_len].fill(0x90);
            libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_EXEC);
            tracing::info!(target_site = format_args!("{:#x}", target_site), thunk_va = format_args!("{:#x}", thunk_va), "patched scheduler post loop guard at 0x144dac7ed");
        }
    }
}

unsafe fn patch_worker_memory_chain_guard(base: usize, info: &ImageInfo) {
    let target_rva = 0x4dd63ab;
    let target_site = base + target_rva;
    let patch_len = 6;
    if target_rva + patch_len >= info.size_of_image as usize {
        return;
    }
    let expected = [0x48, 0x89, 0x51, 0x08, 0xeb, 0xab];
    let slice = unsafe { std::slice::from_raw_parts(target_site as *const u8, patch_len) };
    if slice != expected {
        return;
    }

    let thunk_mem = match alloc_near(base, info.size_of_image as usize, 4096) {
        Ok(p) => p,
        Err(_) => return,
    };
    let thunk_va = thunk_mem as usize;
    let target_continue = base + 0x4dd635c;

    let mut thunk = Vec::with_capacity(48);
    // mov r11, rcx
    thunk.extend_from_slice(&[0x49, 0x89, 0xcb]);
    // shr r11, 32
    thunk.extend_from_slice(&[0x49, 0xc1, 0xeb, 0x20]);
    // dec r11
    thunk.extend_from_slice(&[0x49, 0xff, 0xcb]);
    // cmp r11, 0x7fff
    thunk.extend_from_slice(&[0x49, 0x81, 0xfb, 0xff, 0x7f, 0x00, 0x00]);
    // ja .Lskip
    let ja_skip = thunk.len();
    thunk.extend_from_slice(&[0x77, 0x00]);
    // test cl, 7
    thunk.extend_from_slice(&[0xf6, 0xc1, 0x07]);
    // jnz .Lskip
    let jnz_skip = thunk.len();
    thunk.extend_from_slice(&[0x75, 0x00]);
    // mov [rcx + 8], rdx
    thunk.extend_from_slice(&[0x48, 0x89, 0x51, 0x08]);

    // .Lskip:
    let skip_off = thunk.len();
    thunk[ja_skip + 1] = (skip_off - (ja_skip + 2)) as u8;
    thunk[jnz_skip + 1] = (skip_off - (jnz_skip + 2)) as u8;

    // jmp target_continue (0x144dd635c)
    let next_ip = thunk_va + thunk.len() + 5;
    let disp = (target_continue as i64 - next_ip as i64) as i32;
    thunk.push(0xe9);
    thunk.extend_from_slice(&disp.to_le_bytes());

    #[cfg(unix)]
    unsafe {
        std::ptr::copy_nonoverlapping(thunk.as_ptr(), thunk_mem, thunk.len());
        libc::mprotect(thunk_mem as *mut libc::c_void, 4096, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC);
        let aligned_start = target_site & !4095;
        let aligned_len = (target_site + patch_len - aligned_start).next_multiple_of(4096);
        if libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) == 0 {
            let target_mut = std::slice::from_raw_parts_mut(target_site as *mut u8, patch_len);
            let disp = (thunk_va as i64 - (target_site as i64 + 5)) as i32;
            target_mut[0] = 0xe9;
            target_mut[1..5].copy_from_slice(&disp.to_le_bytes());
            target_mut[5] = 0x90;
            libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_EXEC);
            tracing::info!(target_site = format_args!("{:#x}", target_site), thunk_va = format_args!("{:#x}", thunk_va), "patched worker memory chain guard at 0x144dd63ab");
        }
    }
}

unsafe fn patch_free_list_unlink_guard(base: usize, info: &ImageInfo) {
    let target_rva = 0x55aa4c0;
    let target_site = base + target_rva;
    let patch_len = 57;
    if target_rva + patch_len >= info.size_of_image as usize {
        return;
    }
    let expected = [
        0x48, 0x8b, 0x42, 0x10,
        0x4c, 0x8b, 0x4a, 0x18,
        0x4c, 0x8d, 0x50, 0x18,
        0x48, 0x85, 0xc0,
        0x44, 0x89, 0xc0,
        0x4c, 0x8d, 0x44, 0xc1, 0x30,
    ];
    let slice = unsafe { std::slice::from_raw_parts(target_site as *const u8, expected.len()) };
    if slice != expected {
        return;
    }

    let thunk_mem = match alloc_near(base, info.size_of_image as usize, 4096) {
        Ok(p) => p,
        Err(_) => return,
    };
    let thunk_va = thunk_mem as usize;

    let mut thunk = Vec::with_capacity(160);

    // Validate rcx:
    // mov r11, rcx
    thunk.extend_from_slice(&[0x49, 0x89, 0xcb]);
    // shr r11, 32
    thunk.extend_from_slice(&[0x49, 0xc1, 0xeb, 0x20]);
    // dec r11
    thunk.extend_from_slice(&[0x49, 0xff, 0xcb]);
    // cmp r11, 0x7fff
    thunk.extend_from_slice(&[0x49, 0x81, 0xfb, 0xff, 0x7f, 0x00, 0x00]);
    // ja .Lret (placeholder)
    let ja_ret1_idx = thunk.len();
    thunk.extend_from_slice(&[0x77, 0x00]);

    // Validate rdx:
    // mov r11, rdx
    thunk.extend_from_slice(&[0x49, 0x89, 0xd3]);
    // shr r11, 32
    thunk.extend_from_slice(&[0x49, 0xc1, 0xeb, 0x20]);
    // dec r11
    thunk.extend_from_slice(&[0x49, 0xff, 0xcb]);
    // cmp r11, 0x7fff
    thunk.extend_from_slice(&[0x49, 0x81, 0xfb, 0xff, 0x7f, 0x00, 0x00]);
    // ja .Lret (placeholder)
    let ja_ret2_idx = thunk.len();
    thunk.extend_from_slice(&[0x77, 0x00]);

    // mov rax, [rdx + 0x10]
    thunk.extend_from_slice(&[0x48, 0x8b, 0x42, 0x10]);
    // mov r11, rax
    thunk.extend_from_slice(&[0x49, 0x89, 0xc3]);
    // shr r11, 32
    thunk.extend_from_slice(&[0x49, 0xc1, 0xeb, 0x20]);
    // dec r11
    thunk.extend_from_slice(&[0x49, 0xff, 0xcb]);
    // cmp r11, 0x7fff
    thunk.extend_from_slice(&[0x49, 0x81, 0xfb, 0xff, 0x7f, 0x00, 0x00]);
    // jbe +2
    thunk.extend_from_slice(&[0x76, 0x02]);
    // xor eax, eax
    thunk.extend_from_slice(&[0x31, 0xc0]);
    // mov r11, rax  (save sanitized prev)
    thunk.extend_from_slice(&[0x49, 0x89, 0xc3]);

    // mov r9, [rdx + 0x18]
    thunk.extend_from_slice(&[0x4c, 0x8b, 0x4a, 0x18]);
    // mov r10, r9
    thunk.extend_from_slice(&[0x4d, 0x89, 0xca]);
    // shr r10, 32
    thunk.extend_from_slice(&[0x49, 0xc1, 0xea, 0x20]);
    // dec r10
    thunk.extend_from_slice(&[0x49, 0xff, 0xca]);
    // cmp r10, 0x7fff
    thunk.extend_from_slice(&[0x49, 0x81, 0xfa, 0xff, 0x7f, 0x00, 0x00]);
    // jbe +3
    thunk.extend_from_slice(&[0x76, 0x03]);
    // xor r9, r9
    thunk.extend_from_slice(&[0x4d, 0x31, 0xc9]);

    // lea r10, [rax + 0x18]
    thunk.extend_from_slice(&[0x4c, 0x8d, 0x50, 0x18]);
    // test rax, rax
    thunk.extend_from_slice(&[0x48, 0x85, 0xc0]);
    // mov eax, r8d
    thunk.extend_from_slice(&[0x44, 0x89, 0xc0]);
    // lea r8, [rcx + rax*8 + 0x30]
    thunk.extend_from_slice(&[0x4c, 0x8d, 0x44, 0xc1, 0x30]);
    // lea rax, [rcx + rax*8 + 0x930]
    thunk.extend_from_slice(&[0x48, 0x8d, 0x84, 0xc1, 0x30, 0x09, 0x00, 0x00]);
    // cmovne r8, r10
    thunk.extend_from_slice(&[0x4d, 0x0f, 0x45, 0xc2]);

    // Check r8:
    // movabs r10, 0x130000000
    thunk.extend_from_slice(&[0x49, 0xba, 0x00, 0x00, 0x00, 0x30, 0x01, 0x00, 0x00, 0x00]);
    // cmp r8, r10
    thunk.extend_from_slice(&[0x4d, 0x39, 0xd0]);
    // jb .Lskip_r8
    let jb_r8 = thunk.len();
    thunk.extend_from_slice(&[0x72, 0x00]);
    // movabs r10, 0xffff800000000000
    thunk.extend_from_slice(&[0x49, 0xba, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0xff, 0xff]);
    // test r8, r10
    thunk.extend_from_slice(&[0x4d, 0x85, 0xd0]);
    // jnz .Lskip_r8
    let jnz_r8 = thunk.len();
    thunk.extend_from_slice(&[0x75, 0x00]);
    // test r8b, 7
    thunk.extend_from_slice(&[0x41, 0xf6, 0xc0, 0x07]);
    // jnz .Lskip_r8
    let jnz_r8_align = thunk.len();
    thunk.extend_from_slice(&[0x75, 0x00]);
    // mov [r8], r9
    thunk.extend_from_slice(&[0x4d, 0x89, 0x08]);

    // .Lskip_r8:
    let skip_r8_off = thunk.len();
    thunk[jb_r8 + 1] = (skip_r8_off - (jb_r8 + 2)) as u8;
    thunk[jnz_r8 + 1] = (skip_r8_off - (jnz_r8 + 2)) as u8;
    thunk[jnz_r8_align + 1] = (skip_r8_off - (jnz_r8_align + 2)) as u8;

    // lea r8, [r9 + 0x10]
    thunk.extend_from_slice(&[0x4d, 0x8d, 0x41, 0x10]);
    // test r9, r9
    thunk.extend_from_slice(&[0x4d, 0x85, 0xc9]);
    // cmovne rax, r8
    thunk.extend_from_slice(&[0x49, 0x0f, 0x45, 0xc0]);

    // Check rax:
    // movabs r10, 0x130000000
    thunk.extend_from_slice(&[0x49, 0xba, 0x00, 0x00, 0x00, 0x30, 0x01, 0x00, 0x00, 0x00]);
    // cmp rax, r10
    thunk.extend_from_slice(&[0x4c, 0x39, 0xd0]);
    // jb .Ldone
    let jb_rax = thunk.len();
    thunk.extend_from_slice(&[0x72, 0x00]);
    // movabs r10, 0xffff800000000000
    thunk.extend_from_slice(&[0x49, 0xba, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0xff, 0xff]);
    // test rax, r10
    thunk.extend_from_slice(&[0x4c, 0x85, 0xd0]);
    // jnz .Ldone
    let jnz_rax = thunk.len();
    thunk.extend_from_slice(&[0x75, 0x00]);
    // test al, 7
    thunk.extend_from_slice(&[0xa8, 0x07]);
    // jnz .Ldone
    let jnz_rax_align = thunk.len();
    thunk.extend_from_slice(&[0x75, 0x00]);
    // mov [rax], r11
    thunk.extend_from_slice(&[0x4c, 0x89, 0x18]);

    // .Ldone:
    let done_off = thunk.len();
    thunk[jb_rax + 1] = (done_off - (jb_rax + 2)) as u8;
    thunk[jnz_rax + 1] = (done_off - (jnz_rax + 2)) as u8;
    thunk[jnz_rax_align + 1] = (done_off - (jnz_rax_align + 2)) as u8;
    // ret
    thunk.push(0xc3);

    // .Lret
    let ret_offset = thunk.len();
    thunk[ja_ret1_idx + 1] = (ret_offset - (ja_ret1_idx + 2)) as u8;
    thunk[ja_ret2_idx + 1] = (ret_offset - (ja_ret2_idx + 2)) as u8;
    thunk.push(0xc3);

    #[cfg(unix)]
    unsafe {
        std::ptr::copy_nonoverlapping(thunk.as_ptr(), thunk_mem, thunk.len());
        libc::mprotect(thunk_mem as *mut libc::c_void, 4096, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC);
        let aligned_start = target_site & !4095;
        let aligned_len = (target_site + patch_len - aligned_start).next_multiple_of(4096);
        if libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) == 0 {
            let target_mut = std::slice::from_raw_parts_mut(target_site as *mut u8, patch_len);
            let disp = (thunk_va as i64 - (target_site as i64 + 5)) as i32;
            target_mut[0] = 0xe9;
            target_mut[1..5].copy_from_slice(&disp.to_le_bytes());
            target_mut[5..patch_len].fill(0x90);
            libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_EXEC);
            tracing::info!(target_site = format_args!("{:#x}", target_site), thunk_va = format_args!("{:#x}", thunk_va), "patched free list unlink guard at 0x1455aa4c0");
        }
    }
}

/// Address of the zeroed dummy resource object with a valid no-op vtable, or 0 if not initialized.
pub(crate) fn dummy_resource_va() -> usize {
    DUMMY_RESOURCE_VA.load(std::sync::atomic::Ordering::Relaxed)
}

/// Patches all `vpmaskmov*` / `vmaskmov*` instructions in `base` if running
/// under Wine/Rosetta (or always unless `VICTORY_ROSETTA_MASKMOV=0`).
///
/// # Safety
/// `base` is the mapped image described by `info`, before title code runs.
pub(crate) unsafe fn patch_image(base: usize, info: &ImageInfo) -> Result<usize> {
    unsafe {
        neutralize_watchdogs(base, info);
        patch_clwb(base, info);
        patch_clzero(base, info);
        patch_telemetry_map(base, info);
        patch_rpf_null_device(base, info);
        patch_rpf_mount_guard(base, info);
        patch_gameconfig_watchdog(base, info);
        patch_config_version_guard(base, info);
        patch_vcall_epilogue_watchdog(base, info);
        patch_vcall_bypass(base, info);
        patch_gameconfig_version_call(base, info);
        patch_hash_null_guard(base, info);
        patch_null_assert_traps(base, info);
        patch_dependency_assert_trap(base, info);
        patch_shader_missing_trap(base, info);
        patch_shader_im_null_guard(base, info);
        patch_shader_lookup_dummy(base, info);
        patch_array_search_null_guard(base, info);
        patch_shader_technique_null_guard(base, info);
        patch_tracker_unref_guard(base, info);
        patch_dict_result_null_guard(base, info);
        patch_security_init_fastfail(base, info);
        patch_string_scan_null_guard(base, info);
        patch_manager_field_null_guard(base, info);
        patch_security_check_cookie(base, info);
        patch_abort_terminate_stub(base, info);
        patch_vcall_null_guard(base, info);
        patch_entry_hash_null_guard(base, info);
        patch_entry_hash_second_null_guard(base, info);
        patch_title_hash_worker_null_guard(base, info);
        patch_resource_init_r14_null_guard(base, info);
        patch_event_listener_null_guard(base, info);
        patch_com_factory_null_guard(base, info);
        patch_xbl_initialize_stub(base, info);
        patch_dict_field_null_guard(base, info);
        patch_assert_epilogue_trap(base, info);
        patch_component_equality_null_guard(base, info);
        patch_anim_table_lookup_null_guard(base, info);
        patch_tunables_provider_null_guard(base, info);
        patch_vector_scale_null_guard(base, info);
        patch_node_lookup_null_guard(base, info);
        patch_cmpl_assert_trap(base, info);
        patch_node_lookup_tailcall_null_guard(base, info);
        patch_zero_pointer_guard(base, info);
        patch_rdx_null_guard(base, info);
        patch_heap_alloc_fallback(base, info);
        patch_heap_alloc_buffer_guard(base, info);
        patch_pool_alloc_buffer_guard(base, info);
        patch_queue_config_null_guard(base, info);
        patch_worker_throttle_null_guard(base, info);
        patch_task_queue_size_null_guard(base, info);
        patch_buffer_resize_null_guard(base, info);
        patch_node_unlink_guard(base, info);
        patch_worker_capacity_null_guard(base, info);
        patch_worker_pool_getter_null_guard(base, info);
        patch_worker_notify_null_guard(base, info);
        patch_hash_node_alloc_fallback(base, info);
        patch_monitorx_mwaitx(base, info);
        patch_vcall_rdx_deref_null_guard(base, info);
        patch_epilogue_zero_out_null_guard(base, info);
        patch_tls_null_guard(base, info);
        patch_shader_cleanup_trap(base, info);
        patch_worker_item_null_guard(base, info);
        patch_free_list_unlink_guard(base, info);
        patch_scheduler_loop_guard(base, info);
        patch_scheduler_list_unlink_guard(base, info);
        patch_scheduler_post_loop_guard(base, info);
        patch_worker_memory_chain_guard(base, info);
        patch_tls_store_null_guard(base, info);
        patch_task_table_null_guard(base, info);
        patch_second_task_table_null_guard(base, info);
        patch_tls_array_null_guard(base, info);
        patch_sentinel_store_null_guard(base, info);
        patch_ring_alloc_null_guard(base, info);
        patch_ring_buffer_null_guard(base, info);
        patch_resource_pool_null_guard(base, info);
    }
    if std::env::var_os("VICTORY_ROSETTA_MASKMOV").is_some_and(|v| v == "0") {
        return Ok(0);
    }
    let mut sites: Vec<(usize, usize, Decoded)> = Vec::new();
    for section in info
        .sections
        .iter()
        .filter(|s| s.characteristics & SCN_MEM_EXECUTE != 0)
    {
        let start = base + section.rva as usize;
        let len = section.virtual_size as usize;
        // SAFETY: section is mapped and readable.
        let code = unsafe { std::slice::from_raw_parts(start as *const u8, len) };
        scan_section(code, start, &mut sites);
    }
    if sites.is_empty() {
        return Ok(0);
    }

    // Allocate thunk pages near `base` (up to 192 bytes per site).
    let thunk_bytes = (sites.len() * 192).next_multiple_of(4096);
    let thunk_base = alloc_near(base, info.size_of_image as usize, thunk_bytes)?;
    let mut cursor = 0usize;
    let mut call_targets = Vec::with_capacity(sites.len());

    for &(site_va, insn_len, ref dec) in &sites {
        let thunk_va = thunk_base as usize + cursor;
        let emitted = emit_thunk(dec, site_va, insn_len, thunk_va);
        // SAFETY: `cursor + emitted.len() <= thunk_bytes` and memory is writable.
        unsafe {
            std::ptr::copy_nonoverlapping(
                emitted.as_ptr(),
                thunk_base.add(cursor),
                emitted.len(),
            );
        }
        cursor += emitted.len();
        call_targets.push(thunk_va);
    }

    let _ = cursor;

    #[cfg(windows)]
    {
        let mut old = 0;
        // SAFETY: our thunk allocation.
        if unsafe { VirtualProtect(thunk_base.cast(), thunk_bytes, PAGE_EXECUTE_READ, &mut old) } == 0 {
            bail!(
                "VirtualProtect(maskmov thunks) failed: {}",
                std::io::Error::last_os_error()
            );
        }
        // SAFETY: our process.
        unsafe { FlushInstructionCache(GetCurrentProcess(), thunk_base.cast(), thunk_bytes) };
    }
    #[cfg(not(windows))]
    {
        if unsafe { libc::mprotect(thunk_base.cast(), thunk_bytes, libc::PROT_READ | libc::PROT_EXEC) } != 0 {
            bail!(
                "mprotect(maskmov thunks) failed: {}",
                std::io::Error::last_os_error()
            );
        }
    }

    // Patch executable sections.
    for section in info
        .sections
        .iter()
        .filter(|s| s.characteristics & SCN_MEM_EXECUTE != 0)
    {
        let start = base + section.rva as usize;
        let len = section.virtual_size as usize;
        let end = start + len;
        #[cfg(windows)]
        {
            let mut old = 0;
            // SAFETY: mapped image section.
            if unsafe { VirtualProtect(start as _, len, PAGE_EXECUTE_READWRITE, &mut old) } == 0 {
                bail!(
                    "VirtualProtect(code for maskmov) failed: {}",
                    std::io::Error::last_os_error()
                );
            }
            for (&(site_va, insn_len, _), &target_va) in sites.iter().zip(&call_targets) {
                if site_va >= start && site_va + insn_len <= end {
                    let rel = (target_va as i64) - ((site_va + 5) as i64);
                    // SAFETY: writable section.
                    let slice =
                        unsafe { std::slice::from_raw_parts_mut(site_va as *mut u8, insn_len) };
                    slice[0] = 0xE8; // call rel32
                    slice[1..5].copy_from_slice(&(rel as i32).to_le_bytes());
                    slice[5..].fill(0x90); // nop padding
                }
            }
            // SAFETY: restore protection and flush icache.
            unsafe {
                VirtualProtect(start as _, len, old, &mut old);
                FlushInstructionCache(GetCurrentProcess(), start as _, len);
            }
        }
        #[cfg(not(windows))]
        {
            let aligned_start = start & !4095;
            let aligned_len = (start + len - aligned_start).next_multiple_of(4096);
            if unsafe { libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) } != 0 {
                bail!(
                    "mprotect(code for maskmov) failed: {}",
                    std::io::Error::last_os_error()
                );
            }
            for (&(site_va, insn_len, _), &target_va) in sites.iter().zip(&call_targets) {
                if site_va >= start && site_va + insn_len <= end {
                    let rel = (target_va as i64) - ((site_va + 5) as i64);
                    let slice =
                        unsafe { std::slice::from_raw_parts_mut(site_va as *mut u8, insn_len) };
                    slice[0] = 0xE8; // call rel32
                    slice[1..5].copy_from_slice(&(rel as i32).to_le_bytes());
                    slice[5..].fill(0x90); // nop padding
                }
            }
            unsafe {
                libc::mprotect(aligned_start as *mut libc::c_void, aligned_len, libc::PROT_READ | libc::PROT_EXEC);
            }
        }
    }

    tracing::info!(patched = sites.len(), "AVX masked load/store instructions patched for Rosetta 2");
    Ok(sites.len())
}

#[derive(Clone)]
struct Decoded {
    cvtps2ph_imm: Option<u8>,
    is_store: bool,
    is_256: bool,
    is_64bit_elem: bool,
    vex_x: u8, // 0 or 1 (1 means index has +8)
    vex_b: u8, // 0 or 1 (1 means base/rm has +8)
    data_reg: u8,
    mask_reg: u8,
    tail: Vec<u8>, // ModRM + optional SIB + optional disp
}

fn modrm_len(b: &[u8]) -> Option<usize> {
    let modrm = *b.first()?;
    let (md, rm) = (modrm >> 6, modrm & 7);
    if md == 3 {
        return None; // masked load/store always takes a memory operand
    }
    let mut len = 1;
    let mut base = rm;
    if rm == 4 {
        base = *b.get(1)? & 7;
        len += 1;
    }
    len += match md {
        0 if base == 5 => 4,
        0 => 0,
        1 => 1,
        _ => 4,
    };
    (b.len() >= len).then_some(len)
}

fn scan_section(code: &[u8], base_va: usize, out: &mut Vec<(usize, usize, Decoded)>) {
    let mut i = 0;
    while i + 5 <= code.len() {
        // 3-byte VEX: C4, map_select == 0x03 (0F 3A), W == 0, pp == 0x01 (66), opcode == 0x1D (`vcvtps2ph m64/m128, xmm/ymm, imm8`)
        if code[i] == 0xC4 && (code[i + 1] & 0x1F) == 3 && (code[i + 2] & 0x83) == 1 && code[i + 3] == 0x1D {
            if let Some(ml) = modrm_len(&code[i + 4..]) && i + 4 + ml < code.len() {
                let total_len = 4 + ml + 1; // +1 for imm8
                let b1 = code[i + 1];
                let b2 = code[i + 2];
                let vex_r = ((b1 >> 7) & 1) ^ 1;
                let vex_x = ((b1 >> 6) & 1) ^ 1;
                let vex_b = ((b1 >> 5) & 1) ^ 1;
                let is_256 = ((b2 >> 2) & 1) != 0;
                let modrm = code[i + 4];
                let reg = ((modrm >> 3) & 7) | (vex_r << 3);
                let imm8 = code[i + 4 + ml];
                let dec = Decoded {
                    cvtps2ph_imm: Some(imm8),
                    is_store: true,
                    is_256,
                    is_64bit_elem: false,
                    vex_x,
                    vex_b,
                    data_reg: reg,
                    mask_reg: 0,
                    tail: code[i + 4..i + 4 + ml].to_vec(),
                };
                out.push((base_va + i, total_len, dec));
                i += total_len;
                continue;
            }
        }
        // 3-byte VEX: C4, map_select == 0x02 (0F 38), pp == 0x01 (66)
        if code[i] == 0xC4 && (code[i + 1] & 0x1F) == 2 && (code[i + 2] & 0x03) == 1 {
            let op = code[i + 3];
            let w = (code[i + 2] >> 7) & 1;
            // 0x8C / 0x8E: vpmaskmovd (W=0) / vpmaskmovq (W=1)
            // 0x2C / 0x2E: vmaskmovps (W=0, op=2C/2E)
            // 0x2D / 0x2F: vmaskmovpd (W=0, op=2D/2F)
            let valid_op = matches!(op, 0x8C | 0x8E) || (matches!(op, 0x2C..=0x2F) && w == 0);
            if valid_op && let Some(ml) = modrm_len(&code[i + 4..]) {
                let total_len = 4 + ml;
                // Do not patch if RIP-relative (mod==0 && rm==5) because moving the
                // `lea` into the thunk would change RIP! (Check if any exist: if so we
                // adjust disp32 in the thunk.)
                let b1 = code[i + 1];
                let b2 = code[i + 2];
                let vex_r = ((b1 >> 7) & 1) ^ 1;
                let vex_x = ((b1 >> 6) & 1) ^ 1;
                let vex_b = ((b1 >> 5) & 1) ^ 1;
                let vvvv = ((b2 >> 3) & 0x0F) ^ 0x0F;
                let is_256 = ((b2 >> 2) & 1) != 0;
                let is_64bit_elem = if matches!(op, 0x8C | 0x8E) {
                    w != 0
                } else {
                    matches!(op, 0x2D | 0x2F)
                };
                let is_store = matches!(op, 0x8E | 0x2E | 0x2F);
                let modrm = code[i + 4];
                let reg = ((modrm >> 3) & 7) | (vex_r << 3);
                let (data_reg, mask_reg) = if is_store {
                    (reg, vvvv)
                } else {
                    (reg, vvvv)
                };
                let dec = Decoded {
                    cvtps2ph_imm: None,
                    is_store,
                    is_256,
                    is_64bit_elem,
                    vex_x,
                    vex_b,
                    data_reg,
                    mask_reg,
                    tail: code[i + 4..i + total_len].to_vec(),
                };
                out.push((base_va + i, total_len, dec));
                i += total_len;
                continue;
            }
        }
        i += 1;
    }
}

/// Emits the thunk for one decoded `vpmaskmov*` / `vmaskmov*` instruction.
fn emit_thunk(dec: &Decoded, site_va: usize, insn_len: usize, thunk_va: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(80);
    // 1. If insn_len > 5, adjust `[rsp]` by `insn_len - 5`:
    //    `add qword ptr [rsp], imm8` -> 48 83 04 24 <imm8>
    if insn_len > 5 {
        out.extend_from_slice(&[0x48, 0x83, 0x04, 0x24, (insn_len - 5) as u8]);
    }
    // 2. Save r10, r11, and flags:
    //    push r10 (41 52)
    //    push r11 (41 53)
    //    pushfq   (9C)
    out.extend_from_slice(&[0x41, 0x52, 0x41, 0x53, 0x9C]);

    // 3. Compute effective address into r10 using `lea r10, <mem>`:
    //    Note: if <mem> uses rsp, rsp has shifted by 4 * 8 = 32 bytes (return address + r10 + r11 + rflags)!
    //    Wait: what if <mem> uses r10 as base or index? `lea r10, [...r10...]` reads the old r10
    //    before writing r10, which is completely valid in x86-64!
    //    What if <mem> uses rsp? Let's check if any instruction uses rsp, or we can check `uses_rsp`.
    //    Wait: if <mem> is RIP-relative (`mod == 0 && rm == 5`), we adjust disp32.
    let modrm = dec.tail[0];
    let md = modrm >> 6;
    let rm = modrm & 7;
    let uses_rsp = dec.vex_b == 0 && rm == 4 && (dec.tail[1] & 7) == 4 && md != 3;
    // REX prefix for `lea r10, <mem>`:
    // W=1 (0x48), R=1 (0x04, since r10 is reg 2 + 8), X=vex_x (0x02), B=vex_b (0x01)
    let rex = 0x48 | 0x04 | (dec.vex_x << 1) | dec.vex_b;
    let lea_modrm = (modrm & 0xC7) | (2 << 3); // reg = 2 (r10)
    let lea_start = out.len();
    out.push(rex);
    out.push(0x8D); // LEA
    out.push(lea_modrm);
    out.extend_from_slice(&dec.tail[1..]);
    if md == 0 && rm == 5 {
        // RIP-relative: original target = (site_va + insn_len) + orig_disp
        // new disp = target - (thunk_va + out.len())
        let orig_disp = i32::from_le_bytes(dec.tail[1..5].try_into().unwrap()) as i64;
        let target = (site_va + insn_len) as i64 + orig_disp;
        let new_rip = (thunk_va + out.len()) as i64;
        let new_disp = (target - new_rip) as i32;
        let disp_at = lea_start + 3;
        out[disp_at..disp_at + 4].copy_from_slice(&new_disp.to_le_bytes());
    }
    if uses_rsp {
        // Since we pushed return address (8) + r10 (8) + r11 (8) + rflags (8) = 32 bytes onto rsp,
        // add 32 to r10: `add r10, 32` -> 49 83 C2 20
        out.extend_from_slice(&[0x49, 0x83, 0xC2, 0x20]);
    }

    // 4. Allocate 64 bytes on stack: `sub rsp, 64` -> 48 83 EC 40
    out.extend_from_slice(&[0x48, 0x83, 0xEC, 0x40]);

    if let Some(imm8) = dec.cvtps2ph_imm {
        // Store `vcvtps2ph [rsp], xmm/ymm(data_reg), imm8` onto the stack (never page-guarded),
        // then copy 8 bytes (128-bit source) or 16 bytes (256-bit source) to `[r10]` via scalar `r11`:
        let r_inv = ((dec.data_reg >> 3) & 1) ^ 1;
        let b1 = (r_inv << 7) | 0x60 | 0x03; // ~R, ~X=1, ~B=1, map=3 (0F 3A)
        let b2 = 0x78 | (u8::from(dec.is_256) << 2) | 0x01; // W=0, vvvv=1111, L, pp=1 (66)
        let modrm = 0x04 | ((dec.data_reg & 7) << 3); // [rsp] via SIB 0x24
        out.extend_from_slice(&[0xC4, b1, b2, 0x1D, modrm, 0x24, imm8]);
        // mov r11, [rsp] (4C 8B 1C 24); mov [r10], r11 (4D 89 1A)
        out.extend_from_slice(&[0x4C, 0x8B, 0x1C, 0x24, 0x4D, 0x89, 0x1A]);
        if dec.is_256 {
            // mov r11, [rsp + 8] (4C 8B 5C 24 08); mov [r10 + 8], r11 (4D 89 5A 08)
            out.extend_from_slice(&[0x4C, 0x8B, 0x5C, 0x24, 0x08, 0x4D, 0x89, 0x5A, 0x08]);
        }
    } else if dec.is_store {
        // Store data_reg at [rsp] and mask_reg at [rsp + 32]:
        // vmovdqu [rsp], xmm/ymm(data_reg)
        emit_vmovdqu_store(&mut out, dec.data_reg, dec.is_256, 0);
        // vmovdqu [rsp + 32], xmm/ymm(mask_reg)
        emit_vmovdqu_store(&mut out, dec.mask_reg, dec.is_256, 32);

        let lanes = match (dec.is_256, dec.is_64bit_elem) {
            (false, false) => 4,
            (true, false) => 8,
            (false, true) => 2,
            (true, true) => 4,
        };
        let step = if dec.is_64bit_elem { 8u8 } else { 4u8 };
        for k in 0..lanes {
            let off = k * step;
            let mask_high_byte = 32 + off + (step - 1);
            // cmp byte ptr [rsp + mask_high_byte], 0 -> 80 7C 24 <disp8> 00
            out.extend_from_slice(&[0x80, 0x7C, 0x24, mask_high_byte, 0x00]);
            if dec.is_64bit_elem {
                // jge +10 -> 7D 0A
                // mov r11, [rsp + off] -> 4C 8B 5C 24 <off> (5 bytes)
                // mov [r10 + off], r11 -> 4D 89 5A <off>    (4 bytes, or 3 if off==0: use disp8 always: mod=01 -> 4D 89 5A <off>)
                out.extend_from_slice(&[
                    0x7D, 0x09,
                    0x4C, 0x8B, 0x5C, 0x24, off,
                    0x4D, 0x89, 0x5A, off,
                ]);
            } else {
                // jge +8 -> 7D 08
                // mov r11d, [rsp + off] -> 44 8B 5C 24 <off> (5 bytes)
                // mov [r10 + off], r11d -> 45 89 5A <off>    (4 bytes)
                out.extend_from_slice(&[
                    0x7D, 0x09,
                    0x44, 0x8B, 0x5C, 0x24, off,
                    0x45, 0x89, 0x5A, off,
                ]);
            }
        }
    } else {
        // Masked load!
        // Store mask_reg at [rsp + 32]:
        emit_vmovdqu_store(&mut out, dec.mask_reg, dec.is_256, 32);
        let lanes = match (dec.is_256, dec.is_64bit_elem) {
            (false, false) => 4,
            (true, false) => 8,
            (false, true) => 2,
            (true, true) => 4,
        };
        let step = if dec.is_64bit_elem { 8u8 } else { 4u8 };
        for k in 0..lanes {
            let off = k * step;
            let mask_high_byte = 32 + off + (step - 1);
            // xor r11d, r11d -> 45 31 DB (3 bytes)
            // cmp byte ptr [rsp + mask_high_byte], 0 -> 80 7C 24 <disp8> 00 (5 bytes)
            // jge +4 -> 7D 04
            // mov r11(d), [r10 + off] -> 4D/45 8B 5A <off> (4 bytes)
            // mov [rsp + off], r11(d) -> 4C/44 89 5C 24 <off> (5 bytes)
            let rex_load = if dec.is_64bit_elem { 0x4D } else { 0x45 };
            let rex_store = if dec.is_64bit_elem { 0x4C } else { 0x44 };
            out.extend_from_slice(&[
                0x45, 0x31, 0xDB,
                0x80, 0x7C, 0x24, mask_high_byte, 0x00,
                0x7D, 0x04,
                rex_load, 0x8B, 0x5A, off,
                rex_store, 0x89, 0x5C, 0x24, off,
            ]);
        }
        // Load data_reg from [rsp] (for 128-bit load, vmovdqu xmm clears upper 128 bits of ymm automatically!):
        emit_vmovdqu_load(&mut out, dec.data_reg, dec.is_256, 0);
    }

    // 5. Restore stack, flags, r11, r10, and return:
    //    add rsp, 64 (48 83 C4 40)
    //    popfq       (9D)
    //    pop r11     (41 5B)
    //    pop r10     (41 5A)
    //    ret         (C3)
    out.extend_from_slice(&[
        0x48, 0x83, 0xC4, 0x40,
        0x9D,
        0x41, 0x5B,
        0x41, 0x5A,
        0xC3,
    ]);
    out
}

/// Emits `vmovdqu [rsp + disp8], xmm/ymm(reg)` using 2-byte VEX (`C5`).
fn emit_vmovdqu_store(out: &mut Vec<u8>, reg: u8, is_256: bool, disp8: u8) {
    let r_inv = ((reg >> 3) & 1) ^ 1;
    let l = u8::from(is_256);
    // 2-byte VEX: C5, [~R, vvvv=1111, L, pp=10 (F3)]
    let vex2 = (r_inv << 7) | (0x0F << 3) | (l << 2) | 0x02;
    let modrm = if disp8 == 0 {
        0x04 | ((reg & 7) << 3) // [rsp]
    } else {
        0x44 | ((reg & 7) << 3) // [rsp + disp8]
    };
    out.extend_from_slice(&[0xC5, vex2, 0x7F, modrm, 0x24]);
    if disp8 != 0 {
        out.push(disp8);
    }
}

/// Emits `vmovdqu xmm/ymm(reg), [rsp + disp8]` using 2-byte VEX (`C5`).
fn emit_vmovdqu_load(out: &mut Vec<u8>, reg: u8, is_256: bool, disp8: u8) {
    let r_inv = ((reg >> 3) & 1) ^ 1;
    let l = u8::from(is_256);
    let vex2 = (r_inv << 7) | (0x0F << 3) | (l << 2) | 0x02;
    let modrm = if disp8 == 0 {
        0x04 | ((reg & 7) << 3)
    } else {
        0x44 | ((reg & 7) << 3)
    };
    out.extend_from_slice(&[0xC5, vex2, 0x6F, modrm, 0x24]);
    if disp8 != 0 {
        out.push(disp8);
    }
}

#[cfg(windows)]
fn alloc_near(base: usize, image_size: usize, alloc_bytes: usize) -> Result<*mut u8> {
    const GRANULE: usize = 0x1_0000;
    let above = (base + image_size).next_multiple_of(GRANULE);
    for k in 0..(1usize << 14) {
        for hint in [
            base.checked_sub((k + 1) * GRANULE + alloc_bytes),
            Some(above + k * GRANULE),
        ] {
            let Some(hint) = hint else { continue };
            // SAFETY: fresh allocation at hint.
            let p = unsafe {
                VirtualAlloc(
                    hint as _,
                    alloc_bytes,
                    MEM_COMMIT | MEM_RESERVE,
                    PAGE_READWRITE,
                )
            };
            if !p.is_null() {
                return Ok(p.cast());
            }
        }
    }
    bail!("no free region near the image for Rosetta maskmov thunks")
}

#[cfg(not(windows))]
fn alloc_near(base: usize, _image_size: usize, alloc_bytes: usize) -> Result<*mut u8> {
    static NEXT_SLOT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(32);
    const GRANULE: usize = 0x1_0000;
    for _ in 0..1024 {
        let slot = NEXT_SLOT.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let Some(hint) = base.checked_sub(slot * GRANULE) else { break };
        let p = unsafe {
            libc::mmap(
                hint as *mut libc::c_void,
                alloc_bytes,
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
                unsafe { libc::munmap(p, alloc_bytes); }
            }
        }
    }
    bail!("no free region near the image for Rosetta maskmov thunks")
}
