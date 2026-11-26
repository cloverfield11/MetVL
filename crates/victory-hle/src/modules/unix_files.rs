use std::collections::HashMap;
use std::ffi::{c_char, c_void, CStr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::SystemTime;

use crate::{hle_export, HleExport, HleModule};

pub const INVALID_HANDLE_VALUE: *mut c_void = !0 as *mut c_void;

pub const ERROR_SUCCESS: u32 = 0;
pub const ERROR_FILE_NOT_FOUND: u32 = 2;
pub const ERROR_PATH_NOT_FOUND: u32 = 3;
pub const ERROR_ACCESS_DENIED: u32 = 5;
pub const ERROR_INVALID_HANDLE: u32 = 6;
pub const ERROR_NO_MORE_FILES: u32 = 18;
pub const ERROR_INVALID_PARAMETER: u32 = 87;

use crate::modules::unix_crt::{GetLastError, SetLastError};

static DRIVES: Mutex<Vec<(char, PathBuf)>> = Mutex::new(Vec::new());

pub fn mount_at(letter: char, root: &Path) {
    let mut drives = DRIVES.lock().unwrap_or_else(|e| e.into_inner());
    let letter = letter.to_ascii_uppercase();
    drives.retain(|(l, _)| *l != letter);
    tracing::info!(drive = %letter, root = %root.display(), "unix virtual drive mounted");
    drives.push((letter, root.to_path_buf()));
}

fn path_from_wide(path: *const u16) -> Option<String> {
    if path.is_null() {
        return None;
    }
    let mut len = 0;
    unsafe {
        while *path.add(len) != 0 {
            len += 1;
        }
        let slice = std::slice::from_raw_parts(path, len);
        Some(String::from_utf16_lossy(slice))
    }
}

fn path_from_narrow(path: *const c_char) -> Option<String> {
    if path.is_null() {
        return None;
    }
    unsafe {
        let cstr = CStr::from_ptr(path);
        Some(cstr.to_string_lossy().into_owned())
    }
}

/// Resolves a Win32 path (e.g. `G:\data\game.rpf` or `common:\data\version.txt` or `platform:\...`) into a host Unix path.
pub fn translate_path(win_path: &str) -> PathBuf {
    let clean = win_path.strip_prefix(r"\\?\").unwrap_or(win_path);
    
    // Check for drive letter or named device prefix (e.g. "common:", "platform:", "G:")
    let (letter, prefix_dir, rest) = if let Some(colon_pos) = clean.find(':') {
        let prefix = &clean[..colon_pos];
        let r = &clean[colon_pos + 1..];
        if prefix.len() == 1 {
            let l = prefix.chars().next().unwrap().to_ascii_uppercase();
            (Some(l), None, r)
        } else {
            // Named device prefix like "common", "platform", "update", etc.
            (None, Some(prefix.to_string()), r)
        }
    } else {
        (None, None, clean)
    };

    let drives = DRIVES.lock().unwrap_or_else(|e| e.into_inner());
    let mut base = if let Some(l) = letter {
        if let Some((_, root)) = drives.iter().find(|(drive, _)| *drive == l) {
            root.clone()
        } else if let Some((_, root)) = drives.iter().find(|(drive, _)| *drive == 'G') {
            root.clone()
        } else {
            PathBuf::from(".")
        }
    } else if let Some((_, root)) = drives.iter().find(|(drive, _)| *drive == 'G') {
        root.clone()
    } else {
        PathBuf::from(".")
    };

    if let Some(dir) = prefix_dir {
        base = base.join(dir);
    }

    let mut path = base;
    for part in rest.split(['\\', '/']) {
        if part.is_empty() || part == "." {
            continue;
        }
        if part == ".." {
            path.pop();
        } else {
            // Case-insensitive segment lookup if the directory exists
            let candidate = path.join(part);
            if candidate.exists() {
                path = candidate;
            } else if let Ok(entries) = std::fs::read_dir(&path) {
                let part_lower = part.to_ascii_lowercase();
                let mut matched = false;
                for entry in entries.filter_map(Result::ok) {
                    if entry.file_name().to_string_lossy().to_ascii_lowercase() == part_lower {
                        path = entry.path();
                        matched = true;
                        break;
                    }
                }
                if !matched {
                    path = candidate;
                }
            } else {
                path = candidate;
            }
        }
    }
    path
}

pub struct OpenFile {
    pub file: Mutex<std::fs::File>,
    pub path: PathBuf,
}

static NEXT_HANDLE: AtomicUsize = AtomicUsize::new(0x2000);
static HANDLES: LazyLock<Mutex<HashMap<usize, Arc<OpenFile>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn alloc_handle(f: std::fs::File, p: PathBuf) -> *mut c_void {
    let id = NEXT_HANDLE.fetch_add(8, Ordering::Relaxed);
    let of = Arc::new(OpenFile {
        file: Mutex::new(f),
        path: p,
    });
    HANDLES.lock().unwrap().insert(id, of);
    id as *mut c_void
}

fn get_handle(h: *mut c_void) -> Option<Arc<OpenFile>> {
    if h == INVALID_HANDLE_VALUE || h.is_null() {
        return None;
    }
    let id = h as usize;
    HANDLES.lock().unwrap().get(&id).cloned()
}

fn free_handle(h: *mut c_void) -> bool {
    if h == INVALID_HANDLE_VALUE || h.is_null() {
        return false;
    }
    let id = h as usize;
    HANDLES.lock().unwrap().remove(&id).is_some()
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct FILETIME {
    pub dwLowDateTime: u32,
    pub dwHighDateTime: u32,
}

fn system_time_to_filetime(t: SystemTime) -> FILETIME {
    match t.duration_since(SystemTime::UNIX_EPOCH) {
        Ok(dur) => {
            let secs = dur.as_secs().saturating_add(11_644_473_600);
            let nanos = dur.subsec_nanos();
            let intervals = (secs * 10_000_000) + (nanos / 100) as u64;
            FILETIME {
                dwLowDateTime: intervals as u32,
                dwHighDateTime: (intervals >> 32) as u32,
            }
        }
        Err(_) => FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        },
    }
}

#[repr(C)]
pub struct WIN32_FILE_ATTRIBUTE_DATA {
    pub dwFileAttributes: u32,
    pub ftCreationTime: FILETIME,
    pub ftLastAccessTime: FILETIME,
    pub ftLastWriteTime: FILETIME,
    pub nFileSizeHigh: u32,
    pub nFileSizeLow: u32,
}

#[repr(C)]
pub struct WIN32_FIND_DATAW {
    pub dwFileAttributes: u32,
    pub ftCreationTime: FILETIME,
    pub ftLastAccessTime: FILETIME,
    pub ftLastWriteTime: FILETIME,
    pub nFileSizeHigh: u32,
    pub nFileSizeLow: u32,
    pub dwReserved0: u32,
    pub dwReserved1: u32,
    pub cFileName: [u16; 260],
    pub cAlternateFileName: [u16; 14],
}

pub extern "win64" fn CreateFileW(
    path: *const u16,
    access: u32,
    _share: u32,
    _sec: *const c_void,
    disp: u32,
    _flags: u32,
    _tmpl: *mut c_void,
) -> *mut c_void {
    let Some(win_path) = path_from_wide(path) else {
        SetLastError(ERROR_PATH_NOT_FOUND);
        return INVALID_HANDLE_VALUE;
    };
    let host_path = translate_path(&win_path);
    tracing::info!(win_path = %win_path, host_path = %host_path.display(), disp, access, "unix CreateFileW");

    let mut opts = std::fs::OpenOptions::new();
    const GENERIC_READ: u32 = 0x8000_0000;
    const GENERIC_WRITE: u32 = 0x4000_0000;

    let read = (access & GENERIC_READ) != 0 || access == 0;
    let write = (access & GENERIC_WRITE) != 0;

    opts.read(read);
    opts.write(write);

    const CREATE_NEW: u32 = 1;
    const CREATE_ALWAYS: u32 = 2;
    const OPEN_EXISTING: u32 = 3;
    const OPEN_ALWAYS: u32 = 4;
    const TRUNCATE_EXISTING: u32 = 5;

    match disp {
        CREATE_NEW => {
            opts.create_new(true).write(true);
        }
        CREATE_ALWAYS => {
            opts.create(true).truncate(true).write(true);
        }
        OPEN_EXISTING => {}
        OPEN_ALWAYS => {
            opts.create(true);
        }
        TRUNCATE_EXISTING => {
            opts.truncate(true).write(true);
        }
        _ => {}
    }

    match opts.open(&host_path) {
        Ok(f) => {
            SetLastError(ERROR_SUCCESS);
            alloc_handle(f, host_path)
        }
        Err(e) => {
            tracing::warn!(host_path = %host_path.display(), error = %e, "unix CreateFileW failed");
            SetLastError(if e.kind() == std::io::ErrorKind::NotFound {
                ERROR_FILE_NOT_FOUND
            } else {
                ERROR_ACCESS_DENIED
            });
            INVALID_HANDLE_VALUE
        }
    }
}

pub extern "win64" fn CreateFileA(
    path: *const c_char,
    access: u32,
    share: u32,
    sec: *const c_void,
    disp: u32,
    flags: u32,
    tmpl: *mut c_void,
) -> *mut c_void {
    let Some(win_path) = path_from_narrow(path) else {
        SetLastError(ERROR_PATH_NOT_FOUND);
        return INVALID_HANDLE_VALUE;
    };
    let wide: Vec<u16> = win_path.encode_utf16().chain(std::iter::once(0)).collect();
    CreateFileW(wide.as_ptr(), access, share, sec, disp, flags, tmpl)
}

pub extern "win64" fn CreateFile2(
    path: *const u16,
    access: u32,
    share: u32,
    disp: u32,
    _params: *const c_void,
) -> *mut c_void {
    CreateFileW(path, access, share, std::ptr::null(), disp, 0, std::ptr::null_mut())
}

pub extern "win64" fn ReadFile(
    handle: *mut c_void,
    buffer: *mut u8,
    len: u32,
    read: *mut u32,
    _overlapped: *mut c_void,
) -> i32 {
    let Some(of) = get_handle(handle) else {
        SetLastError(ERROR_INVALID_HANDLE);
        return 0;
    };

    let mut file = of.file.lock().unwrap();
    let slice = unsafe { std::slice::from_raw_parts_mut(buffer, len as usize) };
    use std::io::Read;
    match file.read(slice) {
        Ok(n) => {
            if !read.is_null() {
                unsafe { *read = n as u32; }
            }
            SetLastError(ERROR_SUCCESS);
            1
        }
        Err(_) => {
            SetLastError(ERROR_ACCESS_DENIED);
            0
        }
    }
}

pub extern "win64" fn WriteFile(
    handle: *mut c_void,
    buffer: *const u8,
    len: u32,
    written: *mut u32,
    _overlapped: *mut c_void,
) -> i32 {
    let Some(of) = get_handle(handle) else {
        SetLastError(ERROR_INVALID_HANDLE);
        return 0;
    };
    let mut file = of.file.lock().unwrap();
    let slice = unsafe { std::slice::from_raw_parts(buffer, len as usize) };
    use std::io::Write;
    match file.write(slice) {
        Ok(n) => {
            if !written.is_null() {
                unsafe { *written = n as u32; }
            }
            SetLastError(ERROR_SUCCESS);
            1
        }
        Err(_) => {
            SetLastError(ERROR_ACCESS_DENIED);
            0
        }
    }
}

pub extern "win64" fn GetFileSize(handle: *mut c_void, high: *mut u32) -> u32 {
    let Some(of) = get_handle(handle) else {
        SetLastError(ERROR_INVALID_HANDLE);
        return 0xFFFF_FFFF;
    };
    let file = of.file.lock().unwrap();
    match file.metadata() {
        Ok(meta) => {
            let len = meta.len();
            if !high.is_null() {
                unsafe { *high = (len >> 32) as u32; }
            }
            SetLastError(ERROR_SUCCESS);
            len as u32
        }
        Err(_) => {
            SetLastError(ERROR_INVALID_HANDLE);
            0xFFFF_FFFF
        }
    }
}

pub extern "win64" fn GetFileSizeEx(handle: *mut c_void, size: *mut i64) -> i32 {
    if size.is_null() {
        SetLastError(ERROR_INVALID_PARAMETER);
        return 0;
    }
    let Some(of) = get_handle(handle) else {
        SetLastError(ERROR_INVALID_HANDLE);
        return 0;
    };
    let file = of.file.lock().unwrap();
    match file.metadata() {
        Ok(meta) => {
            unsafe { *size = meta.len() as i64; }
            SetLastError(ERROR_SUCCESS);
            1
        }
        Err(_) => {
            SetLastError(ERROR_INVALID_HANDLE);
            0
        }
    }
}

pub extern "win64" fn SetFilePointer(
    handle: *mut c_void,
    dist_low: i32,
    dist_high: *mut i32,
    method: u32,
) -> u32 {
    let Some(of) = get_handle(handle) else {
        SetLastError(ERROR_INVALID_HANDLE);
        return 0xFFFF_FFFF;
    };
    let mut offset = dist_low as i64;
    if !dist_high.is_null() {
        let h = unsafe { *dist_high } as i64;
        offset = (h << 32) | (dist_low as u32 as i64);
    }
    use std::io::{Seek, SeekFrom};
    let seek_from = match method {
        0 => SeekFrom::Start(offset as u64),
        1 => SeekFrom::Current(offset),
        2 => SeekFrom::End(offset),
        _ => {
            SetLastError(ERROR_INVALID_PARAMETER);
            return 0xFFFF_FFFF;
        }
    };
    let mut file = of.file.lock().unwrap();
    match file.seek(seek_from) {
        Ok(new_pos) => {
            if !dist_high.is_null() {
                unsafe { *dist_high = (new_pos >> 32) as i32; }
            }
            SetLastError(ERROR_SUCCESS);
            new_pos as u32
        }
        Err(_) => {
            SetLastError(ERROR_INVALID_PARAMETER);
            0xFFFF_FFFF
        }
    }
}

pub extern "win64" fn SetFilePointerEx(
    handle: *mut c_void,
    distance: i64,
    new_ptr: *mut i64,
    method: u32,
) -> i32 {
    let Some(of) = get_handle(handle) else {
        SetLastError(ERROR_INVALID_HANDLE);
        return 0;
    };
    use std::io::{Seek, SeekFrom};
    let seek_from = match method {
        0 => SeekFrom::Start(distance as u64),
        1 => SeekFrom::Current(distance),
        2 => SeekFrom::End(distance),
        _ => {
            SetLastError(ERROR_INVALID_PARAMETER);
            return 0;
        }
    };
    let mut file = of.file.lock().unwrap();
    match file.seek(seek_from) {
        Ok(pos) => {
            if !new_ptr.is_null() {
                unsafe { *new_ptr = pos as i64; }
            }
            SetLastError(ERROR_SUCCESS);
            1
        }
        Err(_) => {
            SetLastError(ERROR_INVALID_PARAMETER);
            0
        }
    }
}

pub extern "win64" fn GetFileTime(
    handle: *mut c_void,
    creation: *mut FILETIME,
    access: *mut FILETIME,
    write: *mut FILETIME,
) -> i32 {
    let Some(of) = get_handle(handle) else {
        SetLastError(ERROR_INVALID_HANDLE);
        return 0;
    };
    let file = of.file.lock().unwrap();
    if let Ok(meta) = file.metadata() {
        let created = meta.created().unwrap_or(SystemTime::UNIX_EPOCH);
        let accessed = meta.accessed().unwrap_or(SystemTime::UNIX_EPOCH);
        let modified = meta.modified().unwrap_or(SystemTime::UNIX_EPOCH);
        unsafe {
            if !creation.is_null() { *creation = system_time_to_filetime(created); }
            if !access.is_null() { *access = system_time_to_filetime(accessed); }
            if !write.is_null() { *write = system_time_to_filetime(modified); }
        }
        SetLastError(ERROR_SUCCESS);
        1
    } else {
        SetLastError(ERROR_INVALID_HANDLE);
        0
    }
}

pub extern "win64" fn SetFileTime(
    _handle: *mut c_void,
    _creation: *const FILETIME,
    _access: *const FILETIME,
    _write: *const FILETIME,
) -> i32 {
    SetLastError(ERROR_SUCCESS);
    1
}

pub extern "win64" fn GetFileAttributesW(path: *const u16) -> u32 {
    let Some(win_path) = path_from_wide(path) else {
        SetLastError(ERROR_PATH_NOT_FOUND);
        return 0xFFFF_FFFF;
    };
    let host_path = translate_path(&win_path);
    match std::fs::metadata(&host_path) {
        Ok(m) => {
            SetLastError(ERROR_SUCCESS);
            if m.is_dir() { 0x10 } else { 0x80 }
        }
        Err(_) => {
            SetLastError(ERROR_FILE_NOT_FOUND);
            0xFFFF_FFFF
        }
    }
}

pub extern "win64" fn GetFileAttributesA(path: *const c_char) -> u32 {
    let Some(win_path) = path_from_narrow(path) else {
        SetLastError(ERROR_PATH_NOT_FOUND);
        return 0xFFFF_FFFF;
    };
    let wide: Vec<u16> = win_path.encode_utf16().chain(std::iter::once(0)).collect();
    GetFileAttributesW(wide.as_ptr())
}

pub extern "win64" fn GetFileAttributesExW(
    path: *const u16,
    _level: i32,
    info: *mut WIN32_FILE_ATTRIBUTE_DATA,
) -> i32 {
    if info.is_null() {
        SetLastError(ERROR_INVALID_PARAMETER);
        return 0;
    }
    let Some(win_path) = path_from_wide(path) else {
        SetLastError(ERROR_PATH_NOT_FOUND);
        return 0;
    };
    let host_path = translate_path(&win_path);
    match std::fs::metadata(&host_path) {
        Ok(m) => {
            let created = m.created().unwrap_or(SystemTime::UNIX_EPOCH);
            let accessed = m.accessed().unwrap_or(SystemTime::UNIX_EPOCH);
            let modified = m.modified().unwrap_or(SystemTime::UNIX_EPOCH);
            let len = m.len();
            unsafe {
                (*info).dwFileAttributes = if m.is_dir() { 0x10 } else { 0x80 };
                (*info).ftCreationTime = system_time_to_filetime(created);
                (*info).ftLastAccessTime = system_time_to_filetime(accessed);
                (*info).ftLastWriteTime = system_time_to_filetime(modified);
                (*info).nFileSizeHigh = (len >> 32) as u32;
                (*info).nFileSizeLow = len as u32;
            }
            SetLastError(ERROR_SUCCESS);
            1
        }
        Err(_) => {
            SetLastError(ERROR_FILE_NOT_FOUND);
            0
        }
    }
}

pub extern "win64" fn SetFileAttributesW(_path: *const u16, _attrs: u32) -> i32 {
    SetLastError(ERROR_SUCCESS);
    1
}

pub extern "win64" fn CloseHandle(handle: *mut c_void) -> i32 {
    if handle == INVALID_HANDLE_VALUE || handle.is_null() {
        SetLastError(ERROR_INVALID_HANDLE);
        return 0;
    }
    free_handle(handle);
    SetLastError(ERROR_SUCCESS);
    1
}

pub extern "win64" fn FlushFileBuffers(handle: *mut c_void) -> i32 {
    if let Some(of) = get_handle(handle) {
        let mut f = of.file.lock().unwrap();
        use std::io::Write;
        let _ = f.flush();
    }
    SetLastError(ERROR_SUCCESS);
    1
}

pub extern "win64" fn GetFileType(handle: *mut c_void) -> u32 {
    if handle == INVALID_HANDLE_VALUE || handle.is_null() {
        return 0; // FILE_TYPE_UNKNOWN
    }
    1 // FILE_TYPE_DISK
}

pub extern "win64" fn SetEndOfFile(handle: *mut c_void) -> i32 {
    if let Some(of) = get_handle(handle) {
        let mut f = of.file.lock().unwrap();
        use std::io::Seek;
        if let Ok(pos) = f.stream_position() {
            let _ = f.set_len(pos);
            SetLastError(ERROR_SUCCESS);
            return 1;
        }
    }
    SetLastError(ERROR_INVALID_HANDLE);
    0
}

struct FindSession {
    entries: Vec<std::fs::DirEntry>,
    index: usize,
}

static NEXT_FIND: AtomicUsize = AtomicUsize::new(0x3000);
static FIND_SESSIONS: LazyLock<Mutex<HashMap<usize, FindSession>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn fill_find_data(entry: &std::fs::DirEntry, data: *mut WIN32_FIND_DATAW) {
    if data.is_null() {
        return;
    }
    unsafe {
        std::ptr::write_bytes(data, 0, 1);
        if let Ok(meta) = entry.metadata() {
            (*data).dwFileAttributes = if meta.is_dir() { 0x10 } else { 0x80 };
            let len = meta.len();
            (*data).nFileSizeHigh = (len >> 32) as u32;
            (*data).nFileSizeLow = len as u32;
            let created = meta.created().unwrap_or(SystemTime::UNIX_EPOCH);
            let accessed = meta.accessed().unwrap_or(SystemTime::UNIX_EPOCH);
            let modified = meta.modified().unwrap_or(SystemTime::UNIX_EPOCH);
            (*data).ftCreationTime = system_time_to_filetime(created);
            (*data).ftLastAccessTime = system_time_to_filetime(accessed);
            (*data).ftLastWriteTime = system_time_to_filetime(modified);
        }
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        let utf16: Vec<u16> = name_str.encode_utf16().take(259).collect();
        for (i, &c) in utf16.iter().enumerate() {
            (*data).cFileName[i] = c;
        }
        (*data).cFileName[utf16.len()] = 0;
    }
}

pub extern "win64" fn FindFirstFileW(path: *const u16, data: *mut WIN32_FIND_DATAW) -> *mut c_void {
    let Some(win_path) = path_from_wide(path) else {
        SetLastError(ERROR_PATH_NOT_FOUND);
        return INVALID_HANDLE_VALUE;
    };
    let host_path = translate_path(&win_path);
    let dir_path = if host_path.to_string_lossy().ends_with('*') {
        host_path.parent().unwrap_or(&host_path).to_path_buf()
    } else if host_path.is_dir() {
        host_path
    } else {
        host_path.parent().unwrap_or(&host_path).to_path_buf()
    };

    let entries = match std::fs::read_dir(&dir_path) {
        Ok(read_dir) => read_dir.filter_map(Result::ok).collect(),
        Err(_) => {
            SetLastError(ERROR_FILE_NOT_FOUND);
            return INVALID_HANDLE_VALUE;
        }
    };

    let mut session = FindSession { entries, index: 0 };
    if session.entries.is_empty() {
        SetLastError(ERROR_FILE_NOT_FOUND);
        return INVALID_HANDLE_VALUE;
    }

    fill_find_data(&session.entries[0], data);
    session.index = 1;

    let id = NEXT_FIND.fetch_add(8, Ordering::Relaxed);
    FIND_SESSIONS.lock().unwrap().insert(id, session);
    SetLastError(ERROR_SUCCESS);
    id as *mut c_void
}

pub extern "win64" fn FindFirstFileExW(
    path: *const u16,
    _level: i32,
    data: *mut WIN32_FIND_DATAW,
    _search_op: i32,
    _filter: *const c_void,
    _flags: u32,
) -> *mut c_void {
    FindFirstFileW(path, data)
}

pub extern "win64" fn FindNextFileW(handle: *mut c_void, data: *mut WIN32_FIND_DATAW) -> i32 {
    let id = handle as usize;
    let mut guard = FIND_SESSIONS.lock().unwrap();
    let Some(session) = guard.get_mut(&id) else {
        SetLastError(ERROR_INVALID_HANDLE);
        return 0;
    };
    if session.index >= session.entries.len() {
        SetLastError(ERROR_NO_MORE_FILES);
        return 0;
    }
    fill_find_data(&session.entries[session.index], data);
    session.index += 1;
    SetLastError(ERROR_SUCCESS);
    1
}

pub extern "win64" fn FindClose(handle: *mut c_void) -> i32 {
    let id = handle as usize;
    FIND_SESSIONS.lock().unwrap().remove(&id);
    SetLastError(ERROR_SUCCESS);
    1
}

pub extern "win64" fn GetFullPathNameW(
    path: *const u16,
    buflen: u32,
    buffer: *mut u16,
    part: *mut *mut u16,
) -> u32 {
    let Some(win_path) = path_from_wide(path) else {
        return 0;
    };
    let utf16: Vec<u16> = win_path.encode_utf16().chain(std::iter::once(0)).collect();
    if buflen == 0 || buffer.is_null() {
        return utf16.len() as u32;
    }
    let copy_len = (buflen as usize).min(utf16.len());
    unsafe {
        std::ptr::copy_nonoverlapping(utf16.as_ptr(), buffer, copy_len);
        if !part.is_null() {
            *part = std::ptr::null_mut();
        }
    }
    (utf16.len() - 1) as u32
}

pub extern "win64" fn GetFullPathNameA(
    path: *const c_char,
    buflen: u32,
    buffer: *mut c_char,
    part: *mut *mut c_char,
) -> u32 {
    let Some(win_path) = path_from_narrow(path) else {
        return 0;
    };
    let bytes = win_path.as_bytes();
    if buflen == 0 || buffer.is_null() {
        return (bytes.len() + 1) as u32;
    }
    let copy_len = (buflen as usize - 1).min(bytes.len());
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr().cast(), buffer, copy_len);
        *buffer.add(copy_len) = 0;
        if !part.is_null() {
            *part = std::ptr::null_mut();
        }
    }
    copy_len as u32
}

pub extern "win64" fn CreateDirectoryW(path: *const u16, _sec: *const c_void) -> i32 {
    let Some(win_path) = path_from_wide(path) else {
        SetLastError(ERROR_PATH_NOT_FOUND);
        return 0;
    };
    let host_path = translate_path(&win_path);
    match std::fs::create_dir_all(&host_path) {
        Ok(_) => { SetLastError(ERROR_SUCCESS); 1 }
        Err(_) => { SetLastError(ERROR_ACCESS_DENIED); 0 }
    }
}

pub extern "win64" fn CreateDirectoryA(path: *const c_char, sec: *const c_void) -> i32 {
    let Some(win_path) = path_from_narrow(path) else {
        SetLastError(ERROR_PATH_NOT_FOUND);
        return 0;
    };
    let wide: Vec<u16> = win_path.encode_utf16().chain(std::iter::once(0)).collect();
    CreateDirectoryW(wide.as_ptr(), sec)
}

pub extern "win64" fn DeleteFileW(path: *const u16) -> i32 {
    let Some(win_path) = path_from_wide(path) else {
        SetLastError(ERROR_FILE_NOT_FOUND);
        return 0;
    };
    let host_path = translate_path(&win_path);
    match std::fs::remove_file(&host_path) {
        Ok(_) => { SetLastError(ERROR_SUCCESS); 1 }
        Err(_) => { SetLastError(ERROR_FILE_NOT_FOUND); 0 }
    }
}

pub extern "win64" fn DeleteFileA(path: *const c_char) -> i32 {
    let Some(win_path) = path_from_narrow(path) else {
        SetLastError(ERROR_FILE_NOT_FOUND);
        return 0;
    };
    let wide: Vec<u16> = win_path.encode_utf16().chain(std::iter::once(0)).collect();
    DeleteFileW(wide.as_ptr())
}

pub extern "win64" fn RemoveDirectoryW(path: *const u16) -> i32 {
    let Some(win_path) = path_from_wide(path) else {
        SetLastError(ERROR_PATH_NOT_FOUND);
        return 0;
    };
    let host_path = translate_path(&win_path);
    match std::fs::remove_dir(&host_path) {
        Ok(_) => { SetLastError(ERROR_SUCCESS); 1 }
        Err(_) => { SetLastError(ERROR_ACCESS_DENIED); 0 }
    }
}

pub extern "win64" fn MoveFileExW(from: *const u16, to: *const u16, _flags: u32) -> i32 {
    let Some(win_from) = path_from_wide(from) else { return 0; };
    let Some(win_to) = path_from_wide(to) else { return 0; };
    let host_from = translate_path(&win_from);
    let host_to = translate_path(&win_to);
    match std::fs::rename(&host_from, &host_to) {
        Ok(_) => { SetLastError(ERROR_SUCCESS); 1 }
        Err(_) => { SetLastError(ERROR_ACCESS_DENIED); 0 }
    }
}

pub extern "win64" fn GetDiskFreeSpaceExW(
    _path: *const u16,
    free_bytes: *mut u64,
    total_bytes: *mut u64,
    total_free: *mut u64,
) -> i32 {
    unsafe {
        if !free_bytes.is_null() { *free_bytes = 500 * 1024 * 1024 * 1024; }
        if !total_bytes.is_null() { *total_bytes = 1000 * 1024 * 1024 * 1024; }
        if !total_free.is_null() { *total_free = 500 * 1024 * 1024 * 1024; }
    }
    SetLastError(ERROR_SUCCESS);
    1
}

pub extern "win64" fn GetDiskFreeSpaceW(
    _root: *const u16,
    sectors_per_cluster: *mut u32,
    bytes_per_sector: *mut u32,
    free_clusters: *mut u32,
    total_clusters: *mut u32,
) -> i32 {
    unsafe {
        if !sectors_per_cluster.is_null() { *sectors_per_cluster = 8; }
        if !bytes_per_sector.is_null() { *bytes_per_sector = 512; }
        if !free_clusters.is_null() { *free_clusters = 100_000_000; }
        if !total_clusters.is_null() { *total_clusters = 200_000_000; }
    }
    SetLastError(ERROR_SUCCESS);
    1
}

pub(crate) fn module() -> HleModule {
    HleModule {
        name: "files",
        dlls: &[
            "kernel32.dll",
            "kernelbase.dll",
            "api-ms-win-core-file-*",
            "api-ms-win-core-processenvironment-*",
            "api-ms-win-core-handle-*",
            "api-ms-win-core-errorhandling-*",
        ],
        exports: vec![
            hle_export!(CreateFileW),
            hle_export!(CreateFileA),
            hle_export!(CreateFile2),
            hle_export!(ReadFile),
            hle_export!(WriteFile),
            hle_export!(GetFileSize),
            hle_export!(GetFileSizeEx),
            hle_export!(SetFilePointer),
            hle_export!(SetFilePointerEx),
            hle_export!(GetFileTime),
            hle_export!(SetFileTime),
            hle_export!(GetFileAttributesW),
            hle_export!(GetFileAttributesA),
            hle_export!(GetFileAttributesExW),
            hle_export!(SetFileAttributesW),
            hle_export!(CloseHandle),
            hle_export!(FlushFileBuffers),
            hle_export!(GetFileType),
            hle_export!(SetEndOfFile),
            hle_export!(FindFirstFileW),
            hle_export!(FindFirstFileExW),
            hle_export!(FindNextFileW),
            hle_export!(FindClose),
            hle_export!(GetFullPathNameW),
            hle_export!(GetFullPathNameA),
            hle_export!(CreateDirectoryW),
            hle_export!(CreateDirectoryA),
            hle_export!(DeleteFileW),
            hle_export!(DeleteFileA),
            hle_export!(RemoveDirectoryW),
            hle_export!(MoveFileExW),
            hle_export!(GetDiskFreeSpaceW),
            hle_export!(GetDiskFreeSpaceExW),
        ],
    }
}
