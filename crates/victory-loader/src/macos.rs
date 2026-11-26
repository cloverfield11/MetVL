//! Native macOS Mach-O/Rosetta 2 PE loader for Xbox Scarlett images.
//!
//! Maps PE sections into memory using `mmap`, applies base relocations,
//! resolves and binds IAT imports directly to Rust HLE functions, and
//! prepares threads with proper stack sizes for execution under macOS.

use std::collections::HashSet;
use std::ffi::{c_void};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, Result, bail};
use victory_pe::{ImageInfo, ImportSymbol};

use crate::{
    DLL_PROCESS_ATTACH, DLL_PROCESS_DETACH, ImportResolver, PreparedImage, Provenance, Resolution,
    prepare,
};

/// A title image mapped into this macOS process.
#[derive(Debug, Clone)]
pub struct LoadedImage {
    pub(crate) base: usize,
    pub(crate) size: usize,
    pub(crate) path: PathBuf,
    pub(crate) info: ImageInfo,
}

unsafe impl Send for LoadedImage {}
unsafe impl Sync for LoadedImage {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MissingImport {
    pub dll: String,
    pub symbol: String,
}

/// Outcome of [`LoadedImage::bind_imports`].
#[derive(Debug, Default, Clone)]
pub struct BindReport {
    pub hle: usize,
    pub host: usize,
    pub title: usize,
    pub missing: Vec<MissingImport>,
}

/// What an unimplemented import does when called.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum UnimplementedPolicy {
    #[default]
    Trap,
    ReturnZero,
}

static UNIMPLEMENTED_CALLS: AtomicU64 = AtomicU64::new(0);

pub fn unimplemented_call_count() -> u64 {
    UNIMPLEMENTED_CALLS.load(Ordering::Relaxed)
}

struct ImportSite {
    dll: String,
    symbol: String,
    policy: UnimplementedPolicy,
    calls: AtomicU64,
}

extern "win64" fn unimplemented_import(site: &'static ImportSite) -> u64 {
    eprintln!("runtime        unimplemented import called: {}!{}", site.dll, site.symbol);
    UNIMPLEMENTED_CALLS.fetch_add(1, Ordering::Relaxed);
    site.calls.fetch_add(1, Ordering::Relaxed);
    match site.policy {
        UnimplementedPolicy::ReturnZero => 0,
        UnimplementedPolicy::Trap => {
            eprintln!("runtime        fatal: trapping on unimplemented import {}!{}", site.dll, site.symbol);
            std::process::abort();
        }
    }
}

const THUNK_SIZE: usize = 32;

struct ThunkBlock {
    base: *mut u8,
    len: usize,
    used: usize,
}

impl ThunkBlock {
    fn new(count: usize) -> Result<Self> {
        let len = (count.max(1) * THUNK_SIZE).next_multiple_of(4096);
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_ANON | libc::MAP_PRIVATE,
                -1,
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            bail!("mmap for import stubs failed: {}", std::io::Error::last_os_error());
        }
        Ok(ThunkBlock {
            base: ptr as *mut u8,
            len,
            used: 0,
        })
    }

    fn emit(&mut self, site: &'static ImportSite) -> Result<usize> {
        if self.used + THUNK_SIZE > self.len {
            bail!("import stub block full");
        }
        let mut code = [0xCC_u8; THUNK_SIZE];
        code[0..2].copy_from_slice(&[0x48, 0xB9]); // mov rcx, imm64
        code[2..10].copy_from_slice(&(site as *const ImportSite as u64).to_le_bytes());
        code[10..12].copy_from_slice(&[0x48, 0xB8]); // mov rax, imm64
        let handler = unimplemented_import as extern "win64" fn(&'static ImportSite) -> u64;
        code[12..20].copy_from_slice(&(handler as *const () as u64).to_le_bytes());
        code[20..22].copy_from_slice(&[0xFF, 0xE0]); // jmp rax

        let at = unsafe {
            let at = self.base.add(self.used);
            std::ptr::copy_nonoverlapping(code.as_ptr(), at, THUNK_SIZE);
            at
        };
        self.used += THUNK_SIZE;
        Ok(at as usize)
    }

    fn seal(self) -> Result<()> {
        let ok = unsafe {
            libc::mprotect(
                self.base as *mut libc::c_void,
                self.len,
                libc::PROT_READ | libc::PROT_EXEC,
            )
        };
        if ok != 0 {
            bail!("mprotect for import stubs failed: {}", std::io::Error::last_os_error());
        }
        Ok(())
    }
}

/// Applies standard PE base relocations (.reloc) when loaded base != preferred image_base.
fn apply_relocations(base: usize, delta: i64, info: &ImageInfo) {
    let Some(reloc_sec) = info.sections.iter().find(|s| s.name == ".reloc") else {
        return;
    };
    let mut offset = 0;
    let sec_size = reloc_sec.virtual_size as usize;
    let reloc_base = base + reloc_sec.rva as usize;

    while offset + 8 <= sec_size {
        let page_rva = unsafe { *(reloc_base.wrapping_add(offset) as *const u32) };
        let block_size = unsafe { *(reloc_base.wrapping_add(offset + 4) as *const u32) } as usize;
        if block_size < 8 || offset + block_size > sec_size {
            break;
        }
        let entries_count = (block_size - 8) / 2;
        let entries_ptr = (reloc_base + offset + 8) as *const u16;

        for i in 0..entries_count {
            let entry = unsafe { *entries_ptr.add(i) };
            let typ = entry >> 12;
            let entry_offset = (entry & 0x0FFF) as usize;
            let target_addr = base + page_rva as usize + entry_offset;

            match typ {
                10 => unsafe {
                    // IMAGE_REL_BASED_DIR64
                    let p = target_addr as *mut u64;
                    *p = (*p).wrapping_add(delta as u64);
                },
                3 => unsafe {
                    // IMAGE_REL_BASED_HIGHLOW
                    let p = target_addr as *mut u32;
                    *p = (*p).wrapping_add(delta as u32);
                },
                0 => {} // IMAGE_REL_BASED_ABSOLUTE (padding)
                _ => {}
            }
        }
        offset += block_size;
    }
}

/// Resolves imports through `inner`, then through title DLL exports.
pub struct WithTitleDlls<'a> {
    pub inner: &'a dyn ImportResolver,
    pub dlls: &'a [(String, LoadedImage)],
}

impl ImportResolver for WithTitleDlls<'_> {
    fn resolve(&self, dll: &str, symbol: &ImportSymbol) -> Resolution {
        let found = self.inner.resolve(dll, symbol);
        if found != Resolution::Missing {
            return found;
        }
        self.dlls
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case(dll))
            .and_then(|(_, image)| image.export_symbol(symbol))
            .map_or(Resolution::Missing, |address| Resolution::Found {
                address,
                provenance: Provenance::Title,
            })
    }
}

/// Maps the prepared copy into macOS virtual memory.
pub fn load(prepared: &PreparedImage, _dir: &Path) -> Result<LoadedImage> {
    let size = (prepared.info.size_of_image as usize).next_multiple_of(16384);

    // Try allocating at the preferred image_base first
    let mut mapped = unsafe {
        libc::mmap(
            prepared.info.image_base as *mut libc::c_void,
            size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_ANON | libc::MAP_PRIVATE,
            -1,
            0,
        )
    };

    if mapped == libc::MAP_FAILED {
        // Fallback to any free address space
        mapped = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_ANON | libc::MAP_PRIVATE,
                -1,
                0,
            )
        };
    }

    if mapped == libc::MAP_FAILED {
        bail!("mmap failed for title image (size {size:#x}): {}", std::io::Error::last_os_error());
    }

    let base = mapped as usize;

    // 1. Copy PE headers
    let header_size = (prepared.info.sections.first().map(|s| s.rva).unwrap_or(0x1000) as usize)
        .min(prepared.bytes.len());
    unsafe {
        std::ptr::copy_nonoverlapping(prepared.bytes.as_ptr(), base as *mut u8, header_size);
    }

    // 2. Copy sections into mapped virtual addresses
    for sec in &prepared.info.sections {
        let sec_va = base + sec.rva as usize;
        let file_start = sec.file_offset as usize;
        let file_len = (sec.file_size as usize).min(prepared.bytes.len().saturating_sub(file_start));
        if file_len > 0 {
            unsafe {
                std::ptr::copy_nonoverlapping(
                    prepared.bytes[file_start..].as_ptr(),
                    sec_va as *mut u8,
                    file_len,
                );
            }
        }
    }

    // 3. Apply base relocations if rebased
    let delta = base as i64 - prepared.info.image_base as i64;
    if delta != 0 && prepared.info.has_relocations {
        apply_relocations(base, delta, &prepared.info);
    }

    // 4. Neutralize watchdogs and patch Rosetta maskmov if necessary
    #[cfg(target_arch = "x86_64")]
    unsafe {
        let _ = crate::rosetta::patch_image(base, &prepared.info);
        let _ = crate::tls::redirect(base, &prepared.info);
    }

    // 5. Apply section protections (mprotect)
    for sec in &prepared.info.sections {
        let sec_va = (base + sec.rva as usize) & !4095;
        let sec_len = (sec.virtual_size as usize).next_multiple_of(4096);
        let mut prot = libc::PROT_READ;
        if (sec.characteristics & 0x8000_0000) != 0 || (sec.characteristics & 0x2000_0000 == 0) {
            prot |= libc::PROT_WRITE;
        }
        if (sec.characteristics & 0x2000_0000) != 0 {
            prot |= libc::PROT_EXEC;
        }
        unsafe {
            libc::mprotect(sec_va as *mut libc::c_void, sec_len, prot);
        }
    }

    Ok(LoadedImage {
        base,
        size,
        path: PathBuf::new(),
        info: prepared.info.clone(),
    })
}

/// Maps title DLLs from `title_dir`.
pub fn load_title_dlls(
    info: &ImageInfo,
    title_dir: &Path,
    cache_dir: &Path,
    wanted: &dyn Fn(&str) -> bool,
) -> Result<Vec<(String, LoadedImage)>> {
    let mut loaded: Vec<(String, LoadedImage)> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    let dirs = (title_dir, cache_dir);
    map_imports(info, dirs, wanted, &mut seen, &mut loaded)?;
    Ok(loaded)
}

fn map_imports(
    info: &ImageInfo,
    dirs: (&Path, &Path),
    wanted: &dyn Fn(&str) -> bool,
    seen: &mut HashSet<String>,
    loaded: &mut Vec<(String, LoadedImage)>,
) -> Result<()> {
    for module in &info.imports {
        map_dll(&module.dll, dirs, wanted, seen, loaded)?;
    }
    for module in &info.delay_imports {
        map_dll(&module.dll, dirs, wanted, seen, loaded)?;
    }
    Ok(())
}

fn map_dll(
    name: &str,
    dirs: (&Path, &Path),
    wanted: &dyn Fn(&str) -> bool,
    seen: &mut HashSet<String>,
    loaded: &mut Vec<(String, LoadedImage)>,
) -> Result<()> {
    let name = name.to_ascii_lowercase();
    let path = dirs.0.join(&name);
    if !seen.insert(name.clone()) || !wanted(&name) || !path.is_file() {
        return Ok(());
    }
    let original = std::fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
    let prepared = prepare(&original).with_context(|| format!("preparing {}", path.display()))?;
    let image = load(&prepared, dirs.1).with_context(|| format!("loading {}", path.display()))?;
    map_imports(&image.info, dirs, wanted, seen, loaded)?;
    loaded.push((name, image));
    Ok(())
}

pub fn load_title_dll(
    name: &str,
    title_dir: &Path,
    cache_dir: &Path,
    wanted: &dyn Fn(&str) -> bool,
) -> Result<Vec<(String, LoadedImage)>> {
    let mut loaded = Vec::new();
    let dirs = (title_dir, cache_dir);
    map_dll(name, dirs, wanted, &mut HashSet::new(), &mut loaded)?;
    Ok(loaded)
}

impl LoadedImage {
    pub fn base(&self) -> usize {
        self.base
    }

    pub fn info(&self) -> &ImageInfo {
        &self.info
    }

    pub fn export(&self, name: &str) -> Option<usize> {
        self.info
            .exports
            .iter()
            .find(|e| e.name.as_deref() == Some(name))
            .and_then(|e| e.rva)
            .map(|rva| self.base + rva as usize)
    }

    pub fn export_symbol(&self, symbol: &ImportSymbol) -> Option<usize> {
        match symbol {
            ImportSymbol::Name { name, .. } => self.export(name),
            ImportSymbol::Ordinal(o) => self
                .info
                .exports
                .iter()
                .find(|e| e.ordinal == *o)
                .and_then(|e| e.rva)
                .map(|rva| self.base + rva as usize),
        }
    }

    pub fn bind_imports(
        &self,
        resolver: &dyn ImportResolver,
        policy: UnimplementedPolicy,
    ) -> Result<BindReport> {
        let mut report = BindReport::default();
        let mut slots: Vec<(u32, usize)> = Vec::with_capacity(self.info.import_count());
        let mut unresolved: Vec<(u32, &str, &ImportSymbol)> = Vec::new();

        for module in self.info.imports.iter().chain(&self.info.delay_imports) {
            for entry in &module.entries {
                match resolver.resolve(&module.dll, &entry.symbol) {
                    Resolution::Found {
                        address,
                        provenance,
                    } => {
                        match provenance {
                            Provenance::Hle => report.hle += 1,
                            Provenance::Host => report.host += 1,
                            Provenance::Title => report.title += 1,
                        }
                        slots.push((entry.iat_slot_rva, address));
                    }
                    Resolution::Missing => {
                        unresolved.push((entry.iat_slot_rva, &module.dll, &entry.symbol));
                    }
                }
            }
        }

        if !unresolved.is_empty() {
            let mut block = ThunkBlock::new(unresolved.len())?;
            for (slot, dll, symbol) in unresolved {
                let site: &'static ImportSite = Box::leak(Box::new(ImportSite {
                    dll: dll.to_owned(),
                    symbol: symbol.to_string(),
                    policy,
                    calls: AtomicU64::new(0),
                }));
                slots.push((slot, block.emit(site)?));
                report.missing.push(MissingImport {
                    dll: site.dll.clone(),
                    symbol: site.symbol.clone(),
                });
            }
            block.seal()?;
        }

        self.write_slots(&slots)?;
        tracing::info!(
            hle = report.hle,
            host = report.host,
            missing = report.missing.len(),
            "imports bound (macOS native)"
        );
        Ok(report)
    }

    fn write_slots(&self, slots: &[(u32, usize)]) -> Result<()> {
        for &(rva, address) in slots {
            let slot = (self.base() + rva as usize) as *mut u64;
            let page = (slot as usize) & !4095;
            unsafe {
                libc::mprotect(
                    page as *mut libc::c_void,
                    4096,
                    libc::PROT_READ | libc::PROT_WRITE,
                );
                slot.write_volatile(address as u64);
            }
        }
        Ok(())
    }

    pub unsafe fn run_tls_callbacks(&self, reason: u32) {
        unsafe { self.tls_callbacks(reason, std::ptr::null_mut()) }
    }

    unsafe fn tls_callbacks(&self, reason: u32, reserved: *mut c_void) {
        let Some(tls) = &self.info.tls else { return };
        for (i, &rva) in tls.callback_rvas.iter().enumerate() {
            println!("runtime        running TLS callback {i} at {:#x}...", self.base() + rva as usize);
            type TlsCallback = unsafe extern "win64" fn(*mut c_void, u32, *mut c_void);
            let callback: TlsCallback = unsafe { std::mem::transmute(self.base() + rva as usize) };
            unsafe { callback(self.base as *mut c_void, reason, reserved) };
            println!("runtime        TLS callback {i} completed");
        }
    }

    pub unsafe fn attach(&self) -> Result<()> {
        unsafe { self.run_tls_callbacks(DLL_PROCESS_ATTACH) };
        Ok(())
    }

    pub unsafe fn detach(&self) {
        unsafe { self.run_tls_callbacks(DLL_PROCESS_DETACH) };
    }

    pub unsafe fn unload(self) {
        unsafe { libc::munmap(self.base as *mut libc::c_void, self.size) };
    }

    pub unsafe fn spawn_main(
        self: Arc<Self>,
        dlls: Vec<(String, LoadedImage)>,
    ) -> Result<std::thread::JoinHandle<Result<u32>>> {
        if self.info.entry_rva == 0 {
            bail!("image has no entry point");
        }
        let stack = usize::try_from(self.info.stack_reserve)
            .unwrap_or(usize::MAX)
            .max(1 << 20);
        std::thread::Builder::new()
            .name("title-main".into())
            .stack_size(stack)
            .spawn(move || {
                #[cfg(target_arch = "x86_64")]
                unsafe {
                    crate::tls::update_thread_teb();
                }
                for (name, dll) in &dlls {
                    println!("runtime        attaching DLL {name}...");
                    unsafe { dll.attach() }.with_context(|| format!("attaching {name}"))?;
                }
                println!("runtime        running main image TLS callbacks...");
                unsafe { self.run_tls_callbacks(DLL_PROCESS_ATTACH) };
                println!("runtime        calling title entry point at {:#x}...", self.base + self.info.entry_rva as usize);
                type Entry = unsafe extern "win64" fn(*mut c_void) -> u32;
                let entry: Entry =
                    unsafe { std::mem::transmute(self.base + self.info.entry_rva as usize) };
                let res = unsafe { entry(std::ptr::null_mut()) };
                println!("runtime        title main exited with code {res}");
                Ok(res)
            })
            .context("spawning title main thread")
    }
}
