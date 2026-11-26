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
use windows_sys::Win32::System::Diagnostics::Debug::FlushInstructionCache;
use windows_sys::Win32::System::Memory::{
    MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_READWRITE,
    VirtualAlloc, VirtualProtect,
};
use windows_sys::Win32::System::Threading::GetCurrentProcess;

const SCN_MEM_EXECUTE: u32 = 0x2000_0000;

static DUMMY_RESOURCE_VA: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

unsafe fn neutralize_watchdogs(base: usize, info: &ImageInfo) {
    let mut total = 0;
    for section in info
        .sections
        .iter()
        .filter(|s| s.characteristics & SCN_MEM_EXECUTE != 0)
    {
        let start = base + section.rva as usize;
        let len = section.virtual_size as usize;
        let mut old = 0;
        unsafe {
            if VirtualProtect(start as _, len, PAGE_EXECUTE_READWRITE, &mut old) != 0 {
                let slice = std::slice::from_raw_parts_mut(start as *mut u8, len);
                let mut i = 0;
                while i + 11 <= slice.len() {
                    // c7 04 25 00 00 00 00 xx xx xx xx -> mov dword ptr [0], imm32
                    if slice[i..i + 7] == [0xc7, 0x04, 0x25, 0x00, 0x00, 0x00, 0x00] {
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
    }
    if total > 0 {
        tracing::info!(total, "neutralized intentional mov [0], imm32 hardcrash watchdog aborts");
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
    unsafe { neutralize_watchdogs(base, info); }
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

    // Patch executable sections.
    for section in info
        .sections
        .iter()
        .filter(|s| s.characteristics & SCN_MEM_EXECUTE != 0)
    {
        let start = base + section.rva as usize;
        let len = section.virtual_size as usize;
        let end = start + len;
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
