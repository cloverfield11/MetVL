//! Native C runtime and Win32 primitives for macOS / Unix.
#![allow(non_snake_case)]
#![allow(clippy::not_unsafe_ptr_arg_deref)]

use std::ffi::{c_char, c_void};
use std::sync::atomic::AtomicI32;
use std::time::Instant;

use crate::{HleExport, HleModule, hle_export};

static START_INSTANT: std::sync::LazyLock<Instant> = std::sync::LazyLock::new(Instant::now);
static ERRNO: AtomicI32 = AtomicI32::new(0);
static CMDLINE: &[u8] = b"game_scarlett_master.exe\0";

unsafe extern "C" {
    fn remainderf(x: f32, y: f32) -> f32;
    fn nextafterf(x: f32, y: f32) -> f32;
    fn erff(x: f32) -> f32;
    fn vsnprintf(str: *mut c_char, size: usize, format: *const c_char, ap: *mut c_void) -> i32;
    static __stdinp: *mut libc::FILE;
    static __stdoutp: *mut libc::FILE;
    static __stderrp: *mut libc::FILE;
}

// --- CRT Heap ---

pub extern "win64" fn malloc(size: usize) -> *mut c_void {
    unsafe { libc::malloc(size) }
}

pub extern "win64" fn free(ptr: *mut c_void) {
    if !ptr.is_null() {
        unsafe { libc::free(ptr) }
    }
}

pub extern "win64" fn calloc(count: usize, size: usize) -> *mut c_void {
    unsafe { libc::calloc(count, size) }
}

pub extern "win64" fn realloc(ptr: *mut c_void, size: usize) -> *mut c_void {
    unsafe { libc::realloc(ptr, size) }
}

pub extern "win64" fn _callnewh(_size: usize) -> i32 {
    0
}

pub extern "win64" fn _set_new_mode(mode: i32) -> i32 {
    mode
}

// --- CRT Memory ops ---

pub extern "win64" fn memcpy(dest: *mut c_void, src: *const c_void, count: usize) -> *mut c_void {
    if (dest as usize) < 0x10000 || (src as usize) < 0x10000 || count == 0 {
        return dest;
    }
    unsafe { libc::memcpy(dest, src, count) }
}

pub extern "win64" fn memmove(dest: *mut c_void, src: *const c_void, count: usize) -> *mut c_void {
    if (dest as usize) < 0x10000 || (src as usize) < 0x10000 || count == 0 {
        return dest;
    }
    unsafe { libc::memmove(dest, src, count) }
}

pub extern "win64" fn memset(dest: *mut c_void, val: i32, count: usize) -> *mut c_void {
    if (dest as usize) < 0x10000 || count == 0 {
        return dest;
    }
    unsafe { libc::memset(dest, val, count) }
}

pub extern "win64" fn memcmp(s1: *const c_void, s2: *const c_void, count: usize) -> i32 {
    unsafe { libc::memcmp(s1, s2, count) }
}

pub extern "win64" fn memchr(s: *const c_void, c: i32, n: usize) -> *mut c_void {
    unsafe { libc::memchr(s, c, n) }
}

// --- CRT Strings ---

pub extern "win64" fn strlen(s: *const c_char) -> usize {
    if s.is_null() { return 0; }
    unsafe { libc::strlen(s) }
}

pub extern "win64" fn strcmp(s1: *const c_char, s2: *const c_char) -> i32 {
    if s1.is_null() || s2.is_null() { return 0; }
    unsafe { libc::strcmp(s1, s2) }
}

pub extern "win64" fn strncmp(s1: *const c_char, s2: *const c_char, n: usize) -> i32 {
    if s1.is_null() || s2.is_null() { return 0; }
    unsafe { libc::strncmp(s1, s2, n) }
}

pub extern "win64" fn strcpy(dest: *mut c_char, src: *const c_char) -> *mut c_char {
    unsafe { libc::strcpy(dest, src) }
}

pub extern "win64" fn strcpy_s(dest: *mut c_char, dest_size: usize, src: *const c_char) -> i32 {
    if dest.is_null() || src.is_null() || dest_size == 0 { return 22; }
    let src_len = unsafe { libc::strlen(src) };
    if src_len + 1 > dest_size { return 34; }
    unsafe {
        libc::memcpy(dest.cast(), src.cast(), src_len + 1);
    }
    0
}

pub extern "win64" fn strncpy(dest: *mut c_char, src: *const c_char, n: usize) -> *mut c_char {
    unsafe { libc::strncpy(dest, src, n) }
}

pub extern "win64" fn strncpy_s(dest: *mut c_char, dest_size: usize, src: *const c_char, count: usize) -> i32 {
    if dest.is_null() || src.is_null() || dest_size == 0 { return 22; }
    let copy_len = count.min(dest_size - 1);
    unsafe {
        libc::strncpy(dest, src, copy_len);
        *dest.add(copy_len) = 0;
    }
    0
}

pub extern "win64" fn strcat(dest: *mut c_char, src: *const c_char) -> *mut c_char {
    unsafe { libc::strcat(dest, src) }
}

pub extern "win64" fn strncat(dest: *mut c_char, src: *const c_char, n: usize) -> *mut c_char {
    unsafe { libc::strncat(dest, src, n) }
}

pub extern "win64" fn strcat_s(dest: *mut c_char, dest_size: usize, src: *const c_char) -> i32 {
    if dest.is_null() || src.is_null() { return 22; }
    let cur_len = unsafe { libc::strlen(dest) };
    let src_len = unsafe { libc::strlen(src) };
    if cur_len + src_len + 1 > dest_size { return 34; }
    unsafe { libc::strcpy(dest.add(cur_len), src); }
    0
}

pub extern "win64" fn strchr(s: *const c_char, c: i32) -> *mut c_char {
    unsafe { libc::strchr(s, c) }
}

pub extern "win64" fn strrchr(s: *const c_char, c: i32) -> *mut c_char {
    unsafe { libc::strrchr(s, c) }
}

pub extern "win64" fn strstr(s1: *const c_char, s2: *const c_char) -> *mut c_char {
    unsafe { libc::strstr(s1, s2) }
}

pub extern "win64" fn strcspn(s: *const c_char, reject: *const c_char) -> usize {
    unsafe { libc::strcspn(s, reject) }
}

pub extern "win64" fn strpbrk(s: *const c_char, accept: *const c_char) -> *mut c_char {
    unsafe { libc::strpbrk(s, accept) }
}

pub extern "win64" fn strtok(s: *mut c_char, delim: *const c_char) -> *mut c_char {
    unsafe { libc::strtok(s, delim) }
}

pub extern "win64" fn strtok_s(s: *mut c_char, delim: *const c_char, context: *mut *mut c_char) -> *mut c_char {
    unsafe { libc::strtok_r(s, delim, context) }
}

pub extern "win64" fn tolower(c: i32) -> i32 {
    unsafe { libc::tolower(c) }
}

pub extern "win64" fn toupper(c: i32) -> i32 {
    unsafe { libc::toupper(c) }
}

pub extern "win64" fn isalnum(c: i32) -> i32 {
    unsafe { libc::isalnum(c) }
}

pub extern "win64" fn isalpha(c: i32) -> i32 {
    unsafe { libc::isalpha(c) }
}

pub extern "win64" fn isdigit(c: i32) -> i32 {
    unsafe { libc::isdigit(c) }
}

pub extern "win64" fn islower(c: i32) -> i32 {
    unsafe { libc::islower(c) }
}

pub extern "win64" fn isspace(c: i32) -> i32 {
    unsafe { libc::isspace(c) }
}

pub extern "win64" fn isxdigit(c: i32) -> i32 {
    unsafe { libc::isxdigit(c) }
}

pub extern "win64" fn _stricmp(s1: *const c_char, s2: *const c_char) -> i32 {
    if s1.is_null() && s2.is_null() { return 0; }
    if s1.is_null() { return -1; }
    if s2.is_null() { return 1; }
    unsafe { libc::strcasecmp(s1, s2) }
}

pub extern "win64" fn _strnicmp(s1: *const c_char, s2: *const c_char, n: usize) -> i32 {
    if n == 0 { return 0; }
    if s1.is_null() && s2.is_null() { return 0; }
    if s1.is_null() { return -1; }
    if s2.is_null() { return 1; }
    unsafe { libc::strncasecmp(s1, s2, n) }
}

pub extern "win64" fn wcslen(s: *const u16) -> usize {
    if s.is_null() { return 0; }
    let mut len = 0;
    unsafe {
        while *s.add(len) != 0 {
            len += 1;
        }
    }
    len
}

pub extern "win64" fn wcscmp(s1: *const u16, s2: *const u16) -> i32 {
    if s1.is_null() || s2.is_null() { return 0; }
    let mut i = 0;
    unsafe {
        loop {
            let c1 = *s1.add(i);
            let c2 = *s2.add(i);
            if c1 != c2 {
                return (c1 as i32) - (c2 as i32);
            }
            if c1 == 0 {
                return 0;
            }
            i += 1;
        }
    }
}

pub extern "win64" fn wcsncpy(dest: *mut u16, src: *const u16, n: usize) -> *mut u16 {
    let mut i = 0;
    unsafe {
        while i < n && *src.add(i) != 0 {
            *dest.add(i) = *src.add(i);
            i += 1;
        }
        while i < n {
            *dest.add(i) = 0;
            i += 1;
        }
    }
    dest
}

pub extern "win64" fn wcscat_s(dest: *mut u16, dest_size: usize, src: *const u16) -> i32 {
    let cur_len = wcslen(dest);
    let src_len = wcslen(src);
    if cur_len + src_len + 1 > dest_size { return 34; }
    unsafe {
        for i in 0..=src_len {
            *dest.add(cur_len + i) = *src.add(i);
        }
    }
    0
}

pub extern "win64" fn wcscoll(s1: *const u16, s2: *const u16) -> i32 {
    wcscmp(s1, s2)
}

pub extern "win64" fn _wcsicoll(s1: *const u16, s2: *const u16) -> i32 {
    _wcsnicmp(s1, s2, usize::MAX)
}

pub extern "win64" fn _wcsnicmp(s1: *const u16, s2: *const u16, n: usize) -> i32 {
    let mut i = 0;
    unsafe {
        while i < n {
            let mut c1 = *s1.add(i) as u32;
            let mut c2 = *s2.add(i) as u32;
            if (b'A' as u32..=b'Z' as u32).contains(&c1) { c1 += 32; }
            if (b'A' as u32..=b'Z' as u32).contains(&c2) { c2 += 32; }
            if c1 != c2 {
                return (c1 as i32) - (c2 as i32);
            }
            if c1 == 0 {
                return 0;
            }
            i += 1;
        }
    }
    0
}

pub extern "win64" fn wcsrchr(s: *const u16, c: u16) -> *mut u16 {
    if s.is_null() { return std::ptr::null_mut(); }
    let mut last = std::ptr::null_mut();
    let mut cur = s as *mut u16;
    unsafe {
        while *cur != 0 {
            if *cur == c {
                last = cur;
            }
            cur = cur.add(1);
        }
        if c == 0 {
            last = cur;
        }
    }
    last
}

pub extern "win64" fn wcstok_s(s: *mut u16, _delim: *const u16, _ctx: *mut *mut u16) -> *mut u16 {
    s
}

// --- CRT Math ---

pub extern "win64" fn sin(x: f64) -> f64 { x.sin() }
pub extern "win64" fn sinf(x: f32) -> f32 { x.sin() }
pub extern "win64" fn cos(x: f64) -> f64 { x.cos() }
pub extern "win64" fn cosf(x: f32) -> f32 { x.cos() }
pub extern "win64" fn tan(x: f64) -> f64 { x.tan() }
pub extern "win64" fn tanf(x: f32) -> f32 { x.tan() }
pub extern "win64" fn asin(x: f64) -> f64 { x.asin() }
pub extern "win64" fn asinf(x: f32) -> f32 { x.asin() }
pub extern "win64" fn acos(x: f64) -> f64 { x.acos() }
pub extern "win64" fn acosf(x: f32) -> f32 { x.acos() }
pub extern "win64" fn sinhf(x: f32) -> f32 { x.sinh() }
pub extern "win64" fn atan(x: f64) -> f64 { x.atan() }
pub extern "win64" fn atanf(x: f32) -> f32 { x.atan() }
pub extern "win64" fn atan2(y: f64, x: f64) -> f64 { y.atan2(x) }
pub extern "win64" fn atan2f(y: f32, x: f32) -> f32 { y.atan2(x) }
pub extern "win64" fn exp(x: f64) -> f64 { x.exp() }
pub extern "win64" fn expf(x: f32) -> f32 { x.exp() }
pub extern "win64" fn exp2(x: f64) -> f64 { x.exp2() }
pub extern "win64" fn exp2f(x: f32) -> f32 { x.exp2() }
pub extern "win64" fn log(x: f64) -> f64 { x.ln() }
pub extern "win64" fn logf(x: f32) -> f32 { x.ln() }
pub extern "win64" fn log2(x: f64) -> f64 { x.log2() }
pub extern "win64" fn log2f(x: f32) -> f32 { x.log2() }
pub extern "win64" fn log10f(x: f32) -> f32 { x.log10() }
pub extern "win64" fn pow(x: f64, y: f64) -> f64 { x.powf(y) }
pub extern "win64" fn powf(x: f32, y: f32) -> f32 { x.powf(y) }
pub extern "win64" fn cbrtf(x: f32) -> f32 { x.cbrt() }
pub extern "win64" fn ceilf(x: f32) -> f32 { x.ceil() }
pub extern "win64" fn fmod(x: f64, y: f64) -> f64 { x % y }
pub extern "win64" fn fmodf(x: f32, y: f32) -> f32 { x % y }
pub extern "win64" fn modf(x: f64, iptr: *mut f64) -> f64 {
    let trunc = x.trunc();
    unsafe { *iptr = trunc; }
    x.fract()
}
pub extern "win64" fn modff(x: f32, iptr: *mut f32) -> f32 {
    let trunc = x.trunc();
    unsafe { *iptr = trunc; }
    x.fract()
}
pub extern "win64" fn remainderf_fn(x: f32, y: f32) -> f32 { unsafe { remainderf(x, y) } }
pub extern "win64" fn nextafterf_fn(x: f32, y: f32) -> f32 { unsafe { nextafterf(x, y) } }
pub extern "win64" fn nexttowardf(x: f32, y: f64) -> f32 { unsafe { nextafterf(x, y as f32) } }
pub extern "win64" fn lroundf(x: f32) -> i64 { x.round() as i64 }
pub extern "win64" fn erff_fn(x: f32) -> f32 { unsafe { erff(x) } }
pub extern "win64" fn _isnan(x: f64) -> i32 { if x.is_nan() { 1 } else { 0 } }
pub extern "win64" fn _dtest(x: *const f64) -> i16 { if unsafe { (*x).is_nan() } { 1 } else { 0 } }
pub extern "win64" fn _fdtest(x: *const f32) -> i16 { if unsafe { (*x).is_nan() } { 1 } else { 0 } }
pub extern "win64" fn _fdsign(x: *const f32) -> i16 { if unsafe { (*x).is_sign_negative() } { 1 } else { 0 } }
pub extern "win64" fn __setusermatherr(_f: *mut c_void) {}

// --- Conversions ---

pub extern "win64" fn atoi(s: *const c_char) -> i32 { unsafe { libc::atoi(s) } }
pub extern "win64" fn atof(s: *const c_char) -> f64 { unsafe { libc::atof(s) } }
pub extern "win64" fn atoll(s: *const c_char) -> i64 { unsafe { libc::atoll(s) } }
pub extern "win64" fn strtod(s: *const c_char, end: *mut *mut c_char) -> f64 { unsafe { libc::strtod(s, end) } }
pub extern "win64" fn strtof(s: *const c_char, end: *mut *mut c_char) -> f32 { unsafe { libc::strtof(s, end) } }
pub extern "win64" fn strtol(s: *const c_char, end: *mut *mut c_char, base: i32) -> libc::c_long {
    unsafe { libc::strtol(s, end, base) }
}
pub extern "win64" fn strtoll(s: *const c_char, end: *mut *mut c_char, base: i32) -> i64 {
    unsafe { libc::strtoll(s, end, base) }
}
pub extern "win64" fn strtoul(s: *const c_char, end: *mut *mut c_char, base: i32) -> libc::c_ulong {
    unsafe { libc::strtoul(s, end, base) }
}
pub extern "win64" fn strtoull(s: *const c_char, end: *mut *mut c_char, base: i32) -> u64 {
    unsafe { libc::strtoull(s, end, base) }
}
pub extern "win64" fn _itoa(val: i32, buf: *mut c_char, radix: i32) -> *mut c_char {
    let s = match radix {
        10 => format!("{val}\0"),
        16 => format!("{val:x}\0"),
        8 => format!("{val:o}\0"),
        2 => format!("{val:b}\0"),
        _ => format!("{val}\0"),
    };
    unsafe {
        libc::strcpy(buf, s.as_ptr().cast());
    }
    buf
}
pub extern "win64" fn _strtoi64(s: *const c_char, end: *mut *mut c_char, base: i32) -> i64 {
    unsafe { libc::strtoll(s, end, base) }
}
pub extern "win64" fn _strtoui64(s: *const c_char, end: *mut *mut c_char, base: i32) -> u64 {
    unsafe { libc::strtoull(s, end, base) }
}
pub extern "win64" fn _wtoi(s: *const u16) -> i32 {
    let mut val = 0i32;
    let mut i = 0;
    unsafe {
        while *s.add(i) >= b'0' as u16 && *s.add(i) <= b'9' as u16 {
            val = val * 10 + (*s.add(i) - b'0' as u16) as i32;
            i += 1;
        }
    }
    val
}
pub extern "win64" fn wcstoull(s: *const u16, _end: *mut *mut u16, _base: i32) -> u64 {
    let mut val = 0u64;
    let mut i = 0;
    unsafe {
        while *s.add(i) >= b'0' as u16 && *s.add(i) <= b'9' as u16 {
            val = val * 10 + (*s.add(i) - b'0' as u16) as u64;
            i += 1;
        }
    }
    val
}
pub extern "win64" fn wcstombs(mbstr: *mut c_char, wcstr: *const u16, count: usize) -> usize {
    let mut i = 0;
    unsafe {
        while i < count && *wcstr.add(i) != 0 {
            *mbstr.add(i) = *wcstr.add(i) as u8 as c_char;
            i += 1;
        }
        if i < count {
            *mbstr.add(i) = 0;
        }
    }
    i
}

pub extern "win64" fn GetUserDefaultLocaleName(locale_name: *mut u16, cch_locale_name: i32) -> i32 {
    let name: [u16; 6] = [b'e' as u16, b'n' as u16, b'-' as u16, b'U' as u16, b'S' as u16, 0];
    if !locale_name.is_null() && cch_locale_name >= name.len() as i32 {
        unsafe {
            std::ptr::copy_nonoverlapping(name.as_ptr(), locale_name, name.len());
        }
        name.len() as i32
    } else {
        0
    }
}

pub extern "win64" fn GetUserDefaultLCID() -> u32 {
    0x0409 // en-US
}

pub extern "win64" fn GetSystemDefaultLCID() -> u32 {
    0x0409 // en-US
}

// --- Utility ---

unsafe fn swap_elements(a: *mut u8, b: *mut u8, size: usize) {
    if a == b {
        return;
    }
    unsafe {
        let mut tmp = [0u8; 256];
        let mut rem = size;
        let mut offset = 0;
        while rem > 0 {
            let chunk = rem.min(tmp.len());
            std::ptr::copy_nonoverlapping(a.add(offset), tmp.as_mut_ptr(), chunk);
            std::ptr::copy_nonoverlapping(b.add(offset), a.add(offset), chunk);
            std::ptr::copy_nonoverlapping(tmp.as_ptr(), b.add(offset), chunk);
            rem -= chunk;
            offset += chunk;
        }
    }
}

unsafe fn qsort_impl(
    base: *mut u8,
    count: usize,
    size: usize,
    cmp: extern "win64" fn(*const c_void, *const c_void) -> i32,
) {
    if count <= 1 {
        return;
    }
    unsafe {
        if count < 16 {
            let mut tmp = vec![0u8; size];
            for i in 1..count {
                let cur = base.add(i * size);
                std::ptr::copy_nonoverlapping(cur, tmp.as_mut_ptr(), size);
                let mut j = i;
                while j > 0 {
                    let prev = base.add((j - 1) * size);
                    if cmp(prev as *const c_void, tmp.as_ptr() as *const c_void) > 0 {
                        std::ptr::copy_nonoverlapping(prev, base.add(j * size), size);
                        j -= 1;
                    } else {
                        break;
                    }
                }
                std::ptr::copy_nonoverlapping(tmp.as_ptr(), base.add(j * size), size);
            }
            return;
        }

        let pivot_idx = count / 2;
        swap_elements(base.add(pivot_idx * size), base.add((count - 1) * size), size);
        let pivot = base.add((count - 1) * size);

        let mut i = 0;
        for j in 0..(count - 1) {
            let elem_j = base.add(j * size);
            if cmp(elem_j as *const c_void, pivot as *const c_void) <= 0 {
                swap_elements(base.add(i * size), elem_j, size);
                i += 1;
            }
        }
        swap_elements(base.add(i * size), base.add((count - 1) * size), size);

        if i > 0 {
            qsort_impl(base, i, size, cmp);
        }
        if i + 1 < count {
            qsort_impl(base.add((i + 1) * size), count - (i + 1), size, cmp);
        }
    }
}

pub extern "win64" fn qsort(
    base: *mut c_void,
    count: usize,
    size: usize,
    cmp: Option<extern "win64" fn(*const c_void, *const c_void) -> i32>,
) {
    if base.is_null() || count <= 1 || size == 0 {
        return;
    }
    if let Some(cmp_fn) = cmp {
        unsafe {
            qsort_impl(base as *mut u8, count, size, cmp_fn);
        }
    }
}

pub extern "win64" fn bsearch(
    key: *const c_void,
    base: *const c_void,
    count: usize,
    size: usize,
    cmp: Option<extern "win64" fn(*const c_void, *const c_void) -> i32>,
) -> *mut c_void {
    if key.is_null() || base.is_null() || count == 0 || size == 0 {
        return std::ptr::null_mut();
    }
    let Some(cmp_fn) = cmp else { return std::ptr::null_mut(); };
    let mut low = 0;
    let mut high = count;
    while low < high {
        let mid = low + (high - low) / 2;
        let mid_ptr = unsafe { (base as *const u8).add(mid * size) as *const c_void };
        let res = cmp_fn(key, mid_ptr);
        if res < 0 {
            high = mid;
        } else if res > 0 {
            low = mid + 1;
        } else {
            return mid_ptr as *mut c_void;
        }
    }
    std::ptr::null_mut()
}

pub extern "win64" fn rand() -> i32 { unsafe { libc::rand() } }
pub extern "win64" fn srand(seed: u32) { unsafe { libc::srand(seed) } }

// --- CRT Runtime lifecycle & table dispatch ---

pub unsafe extern "win64" fn _initterm(start: *const Option<unsafe extern "win64" fn()>, end: *const Option<unsafe extern "win64" fn()>) {
    unsafe {
        let mut cur = start;
        let mut idx = 0;
        while cur < end {
            if let Some(f) = *cur {
                eprintln!("runtime        _initterm calling initializer {idx} at {:#x}", f as *const () as usize);
                f();
            }
            cur = cur.add(1);
            idx += 1;
        }
    }
}

pub unsafe extern "win64" fn _initterm_e(
    start: *const Option<unsafe extern "win64" fn() -> i32>,
    end: *const Option<unsafe extern "win64" fn() -> i32>,
) -> i32 {
    unsafe {
        let mut cur = start;
        let mut idx = 0;
        while cur < end {
            if let Some(f) = *cur {
                eprintln!("runtime        _initterm_e calling initializer {idx} at {:#x}", f as *const () as usize);
                let ret = f();
                eprintln!("runtime        _initterm_e initializer {idx} returned {ret}");
                if ret != 0 {
                    return ret;
                }
            }
            cur = cur.add(1);
            idx += 1;
        }
    }
    0
}

pub extern "win64" fn _configure_narrow_argv(_mode: i32) -> i32 { 0 }
pub extern "win64" fn _initialize_narrow_environment() -> i32 { 0 }
pub extern "win64" fn _initialize_onexit_table(table: *mut c_void) -> i32 {
    if !table.is_null() {
        unsafe {
            let p = table as *mut *mut c_void;
            *p = usize::MAX as *mut c_void;
            *p.add(1) = usize::MAX as *mut c_void;
            *p.add(2) = usize::MAX as *mut c_void;
        }
    }
    0
}
pub extern "win64" fn _register_onexit_function(_table: *mut c_void, _f: *mut c_void) -> i32 { 0 }
pub extern "win64" fn _execute_onexit_table(_table: *mut c_void) -> i32 { 0 }
pub extern "win64" fn _crt_atexit(_f: *mut c_void) -> i32 { 0 }
pub extern "win64" fn _crt_at_quick_exit(_f: *mut c_void) -> i32 { 0 }
pub extern "win64" fn _register_thread_local_exe_atexit_callback(_f: *mut c_void) -> i32 { 0 }
pub extern "win64" fn _seh_filter_dll(_code: u32, _info: *mut c_void) -> i32 { 0 }
pub extern "win64" fn _seh_filter_exe(_code: u32, _info: *mut c_void) -> i32 { 0 }
pub extern "win64" fn _set_app_type(_type: i32) {}
pub extern "win64" fn _get_narrow_winmain_command_line() -> *const c_char {
    CMDLINE.as_ptr().cast()
}

static CMDLINE_W: &[u16] = &[
    b'g' as u16, b'a' as u16, b'm' as u16, b'e' as u16, b'_' as u16,
    b's' as u16, b'c' as u16, b'a' as u16, b'r' as u16, b'l' as u16,
    b'e' as u16, b't' as u16, b't' as u16, b'_' as u16, b'm' as u16,
    b'a' as u16, b's' as u16, b't' as u16, b'e' as u16, b'r' as u16,
    b'.' as u16, b'e' as u16, b'x' as u16, b'e' as u16, 0,
];

pub extern "win64" fn GetCommandLineA() -> *const c_char {
    CMDLINE.as_ptr().cast()
}

pub extern "win64" fn GetCommandLineW() -> *const u16 {
    CMDLINE_W.as_ptr()
}
pub extern "win64" fn _cexit() {}
pub extern "win64" fn _c_exit() {}
pub extern "win64" fn _exit(_code: i32) {
    std::process::exit(_code);
}
pub extern "win64" fn _invalid_parameter_noinfo() {}
pub extern "win64" fn _set_invalid_parameter_handler(_handler: *mut c_void) -> *mut c_void { std::ptr::null_mut() }
pub extern "win64" fn _invoke_watson(_msg: *const u16, _f: *const u16, _file: *const u16, _line: u32, _reserved: usize) {}
pub extern "win64" fn _wassert(_msg: *const u16, _file: *const u16, _line: u32) {}
pub extern "win64" fn _configthreadlocale(_flags: i32) -> i32 { 0 }
pub extern "win64" fn localeconv() -> *mut c_void {
    unsafe { libc::localeconv() as *mut c_void }
}

pub extern "win64" fn _errno() -> *mut i32 {
    ERRNO.as_ptr()
}
pub extern "win64" fn _get_errno(out: *mut i32) -> i32 {
    if !out.is_null() {
        unsafe { *out = ERRNO.load(std::sync::atomic::Ordering::Relaxed); }
    }
    0
}
pub extern "win64" fn _set_errno(val: i32) -> i32 {
    ERRNO.store(val, std::sync::atomic::Ordering::Relaxed);
    0
}
pub extern "win64" fn strerror(err: i32) -> *mut c_char {
    unsafe { libc::strerror(err) }
}

// --- Time ---

pub extern "win64" fn _time64(out: *mut i64) -> i64 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    if !out.is_null() {
        unsafe { *out = now; }
    }
    now
}

pub extern "win64" fn _difftime64(t1: i64, t2: i64) -> f64 {
    (t1 - t2) as f64
}

pub extern "win64" fn _localtime64_s(out: *mut c_void, time: *const i64) -> i32 {
    if out.is_null() || time.is_null() { return 22; }
    let t = unsafe { *time };
    unsafe {
        let tm = libc::localtime(&t as *const i64 as *const libc::time_t);
        if !tm.is_null() {
            std::ptr::copy_nonoverlapping(tm as *const u8, out as *mut u8, std::mem::size_of::<libc::tm>());
            0
        } else {
            22
        }
    }
}

pub extern "win64" fn _gmtime64_s(out: *mut c_void, time: *const i64) -> i32 {
    if out.is_null() || time.is_null() { return 22; }
    let t = unsafe { *time };
    unsafe {
        let tm = libc::gmtime(&t as *const i64 as *const libc::time_t);
        if !tm.is_null() {
            std::ptr::copy_nonoverlapping(tm as *const u8, out as *mut u8, std::mem::size_of::<libc::tm>());
            0
        } else {
            22
        }
    }
}

pub extern "win64" fn _gmtime64(time: *const i64) -> *mut c_void {
    if time.is_null() { return std::ptr::null_mut(); }
    let t = unsafe { *time };
    unsafe { libc::gmtime(&t as *const i64 as *const libc::time_t) as *mut c_void }
}

pub extern "win64" fn _mktime64(tm: *mut c_void) -> i64 {
    unsafe { libc::mktime(tm as *mut libc::tm) as i64 }
}

pub extern "win64" fn _mkgmtime64(tm: *mut c_void) -> i64 {
    unsafe { libc::timegm(tm as *mut libc::tm) as i64 }
}

pub extern "win64" fn _ftime64(_tb: *mut c_void) {}

pub extern "win64" fn strftime(buf: *mut c_char, maxsize: usize, format: *const c_char, tm: *const c_void) -> usize {
    unsafe { libc::strftime(buf, maxsize, format, tm as *const libc::tm) }
}

// --- Stdio ---

pub extern "win64" fn __acrt_iob_func(idx: u32) -> *mut c_void {
    match idx {
        0 => unsafe { __stdinp as *mut c_void },
        1 => unsafe { __stdoutp as *mut c_void },
        2 => unsafe { __stderrp as *mut c_void },
        _ => std::ptr::null_mut(),
    }
}

pub extern "win64" fn __p__commode() -> *mut i32 {
    static mut COMMODE: i32 = 0;
    std::ptr::addr_of_mut!(COMMODE)
}

pub extern "win64" fn _set_fmode(_mode: i32) -> i32 { 0 }

pub extern "win64" fn fopen(filename: *const c_char, mode: *const c_char) -> *mut c_void {
    unsafe { libc::fopen(filename, mode) as *mut c_void }
}

pub extern "win64" fn _wfopen(filename: *const u16, mode: *const u16) -> *mut c_void {
    let fn_len = wcslen(filename);
    let mut fn_utf8 = Vec::with_capacity(fn_len + 1);
    unsafe {
        for i in 0..fn_len {
            fn_utf8.push(*filename.add(i) as u8);
        }
    }
    fn_utf8.push(0);

    let mode_len = wcslen(mode);
    let mut mode_utf8 = Vec::with_capacity(mode_len + 1);
    unsafe {
        for i in 0..mode_len {
            mode_utf8.push(*mode.add(i) as u8);
        }
    }
    mode_utf8.push(0);

    unsafe { libc::fopen(fn_utf8.as_ptr().cast(), mode_utf8.as_ptr().cast()) as *mut c_void }
}

pub extern "win64" fn fclose(f: *mut c_void) -> i32 {
    unsafe { libc::fclose(f as *mut libc::FILE) }
}

pub extern "win64" fn fread(ptr: *mut c_void, size: usize, count: usize, f: *mut c_void) -> usize {
    unsafe { libc::fread(ptr, size, count, f as *mut libc::FILE) }
}

pub extern "win64" fn fwrite(ptr: *const c_void, size: usize, count: usize, f: *mut c_void) -> usize {
    unsafe { libc::fwrite(ptr, size, count, f as *mut libc::FILE) }
}

pub extern "win64" fn fseek(f: *mut c_void, offset: libc::c_long, origin: i32) -> i32 {
    unsafe { libc::fseek(f as *mut libc::FILE, offset, origin) }
}

pub extern "win64" fn _fseeki64(f: *mut c_void, offset: i64, origin: i32) -> i32 {
    unsafe { libc::fseeko(f as *mut libc::FILE, offset, origin) }
}

pub extern "win64" fn ftell(f: *mut c_void) -> libc::c_long {
    unsafe { libc::ftell(f as *mut libc::FILE) }
}

pub extern "win64" fn _ftelli64(f: *mut c_void) -> i64 {
    unsafe { libc::ftello(f as *mut libc::FILE) }
}

pub extern "win64" fn fflush(f: *mut c_void) -> i32 {
    unsafe { libc::fflush(f as *mut libc::FILE) }
}

pub extern "win64" fn fgetc(f: *mut c_void) -> i32 {
    unsafe { libc::fgetc(f as *mut libc::FILE) }
}

pub extern "win64" fn fputc(c: i32, f: *mut c_void) -> i32 {
    unsafe { libc::fputc(c, f as *mut libc::FILE) }
}

pub extern "win64" fn ferror(f: *mut c_void) -> i32 {
    unsafe { libc::ferror(f as *mut libc::FILE) }
}

pub extern "win64" fn rewind(f: *mut c_void) {
    unsafe { libc::rewind(f as *mut libc::FILE) }
}

pub extern "win64" fn ungetc(c: i32, f: *mut c_void) -> i32 {
    unsafe { libc::ungetc(c, f as *mut libc::FILE) }
}

pub extern "win64" fn setvbuf(f: *mut c_void, buf: *mut c_char, mode: i32, size: usize) -> i32 {
    unsafe { libc::setvbuf(f as *mut libc::FILE, buf, mode, size) }
}

pub extern "win64" fn _lock_file(_f: *mut c_void) {}
pub extern "win64" fn _unlock_file(_f: *mut c_void) {}
pub extern "win64" fn _wstat64(_path: *const u16, _buf: *mut c_void) -> i32 { -1 }
pub extern "win64" fn remove(path: *const c_char) -> i32 { unsafe { libc::remove(path) } }

fn write_dec(buf: &mut [u8; 32], mut val: u64) -> &[u8] {
    if val == 0 {
        buf[31] = b'0';
        return &buf[31..];
    }
    let mut i = 32;
    while val > 0 {
        i -= 1;
        buf[i] = b'0' + (val % 10) as u8;
        val /= 10;
    }
    &buf[i..]
}

fn write_hex(buf: &mut [u8; 32], mut val: u64, upper: bool) -> &[u8] {
    if val == 0 {
        buf[31] = b'0';
        return &buf[31..];
    }
    let digits = if upper { b"0123456789ABCDEF" } else { b"0123456789abcdef" };
    let mut i = 32;
    while val > 0 {
        i -= 1;
        buf[i] = digits[(val & 0xf) as usize];
        val >>= 4;
    }
    &buf[i..]
}

unsafe fn format_win64_vsprintf(
    out: *mut c_char,
    len: usize,
    format: *const c_char,
    valist: *mut c_void,
) -> i32 {
    if out.is_null() || len == 0 {
        return 0;
    }
    if format.is_null() {
        unsafe { *out = 0; }
        return 0;
    }

    let mut args = valist as *const u64;
    let mut written = 0;
    let mut f_ptr = format as *const u8;

    macro_rules! putc {
        ($c:expr) => {
            if written + 1 < len {
                unsafe { *out.add(written) = $c as c_char; }
                written += 1;
            }
        };
    }

    macro_rules! puts {
        ($s:expr) => {
            for &b in $s {
                if b == 0 { break; }
                putc!(b);
            }
        };
    }

    unsafe {
        while *f_ptr != 0 {
            let ch = *f_ptr;
            if ch != b'%' {
                putc!(ch);
                f_ptr = f_ptr.add(1);
                continue;
            }

            f_ptr = f_ptr.add(1);
            if *f_ptr == b'%' {
                putc!(b'%');
                f_ptr = f_ptr.add(1);
                continue;
            }

            let mut width = 0usize;
            let mut zero_pad = false;
            let mut is_long = 0;

            if *f_ptr == b'0' {
                zero_pad = true;
                f_ptr = f_ptr.add(1);
            }

            while (*f_ptr).is_ascii_digit() {
                width = width * 10 + (*f_ptr - b'0') as usize;
                f_ptr = f_ptr.add(1);
            }

            if *f_ptr == b'.' {
                f_ptr = f_ptr.add(1);
                while (*f_ptr).is_ascii_digit() {
                    f_ptr = f_ptr.add(1);
                }
            }

            while *f_ptr == b'l' || *f_ptr == b'h' || *f_ptr == b'z' || *f_ptr == b'I' {
                if *f_ptr == b'l' { is_long += 1; }
                f_ptr = f_ptr.add(1);
            }

            let spec = *f_ptr;
            if spec == 0 { break; }
            f_ptr = f_ptr.add(1);

            if args.is_null() {
                continue;
            }

            let arg = *args;
            args = args.add(1);

            match spec {
                b's' => {
                    let str_ptr = arg as *const u8;
                    if !str_ptr.is_null() {
                        let mut p = str_ptr;
                        while *p != 0 {
                            putc!(*p);
                            p = p.add(1);
                        }
                    } else {
                        puts!(b"(null)");
                    }
                }
                b'S' => {
                    let wstr_ptr = arg as *const u16;
                    if !wstr_ptr.is_null() {
                        let mut p = wstr_ptr;
                        while *p != 0 {
                            putc!((*p & 0xff) as u8);
                            p = p.add(1);
                        }
                    } else {
                        puts!(b"(null)");
                    }
                }
                b'd' | b'i' => {
                    let val = if is_long >= 2 { arg as i64 } else { arg as i32 as i64 };
                    let mut buf = [0u8; 32];
                    let s = if val < 0 {
                        putc!(b'-');
                        let u = val.unsigned_abs();
                        write_dec(&mut buf, u)
                    } else {
                        write_dec(&mut buf, val as u64)
                    };
                    if width > s.len() {
                        let pad_char = if zero_pad { b'0' } else { b' ' };
                        for _ in 0..(width - s.len()) {
                            putc!(pad_char);
                        }
                    }
                    puts!(s);
                }
                b'u' => {
                    let val = if is_long >= 2 { arg } else { arg as u32 as u64 };
                    let mut buf = [0u8; 32];
                    let s = write_dec(&mut buf, val);
                    if width > s.len() {
                        let pad_char = if zero_pad { b'0' } else { b' ' };
                        for _ in 0..(width - s.len()) {
                            putc!(pad_char);
                        }
                    }
                    puts!(s);
                }
                b'x' | b'X' | b'p' => {
                    let val = if spec == b'p' || is_long >= 1 { arg } else { arg as u32 as u64 };
                    if spec == b'p' {
                        puts!(b"0x");
                    }
                    let mut buf = [0u8; 32];
                    let s = write_hex(&mut buf, val, spec == b'X');
                    if width > s.len() {
                        let pad_char = if zero_pad { b'0' } else { b' ' };
                        for _ in 0..(width - s.len()) {
                            putc!(pad_char);
                        }
                    }
                    puts!(s);
                }
                b'c' => {
                    putc!(arg as u8);
                }
                _ => {
                    putc!(spec);
                }
            }
        }

        if written < len {
            *out.add(written) = 0;
        } else if len > 0 {
            *out.add(len - 1) = 0;
        }
    }
    written as i32
}

pub extern "win64" fn __stdio_common_vsprintf(
    _options: u64,
    out: *mut c_char,
    len: usize,
    format: *const c_char,
    _locale: *mut c_void,
    valist: *mut c_void,
) -> i32 {
    unsafe { format_win64_vsprintf(out, len, format, valist) }
}

pub extern "win64" fn __stdio_common_vsprintf_s(
    options: u64,
    out: *mut c_char,
    len: usize,
    format: *const c_char,
    locale: *mut c_void,
    valist: *mut c_void,
) -> i32 {
    __stdio_common_vsprintf(options, out, len, format, locale, valist)
}

pub extern "win64" fn __stdio_common_vsnprintf_s(
    options: u64,
    out: *mut c_char,
    len: usize,
    _max: usize,
    format: *const c_char,
    locale: *mut c_void,
    valist: *mut c_void,
) -> i32 {
    __stdio_common_vsprintf(options, out, len, format, locale, valist)
}

pub extern "win64" fn __stdio_common_vfprintf(
    _options: u64,
    f: *mut c_void,
    format: *const c_char,
    _locale: *mut c_void,
    _valist: *mut c_void,
) -> i32 {
    unsafe { libc::fputs(format, f as *mut libc::FILE) }
}

pub extern "win64" fn __stdio_common_vswprintf(
    _options: u64,
    out: *mut u16,
    len: usize,
    format: *const u16,
    _locale: *mut c_void,
    _valist: *mut c_void,
) -> i32 {
    wcsncpy(out, format, len);
    wcslen(out) as i32
}

pub extern "win64" fn __stdio_common_vswprintf_s(
    options: u64,
    out: *mut u16,
    len: usize,
    format: *const u16,
    locale: *mut c_void,
    valist: *mut c_void,
) -> i32 {
    __stdio_common_vswprintf(options, out, len, format, locale, valist)
}

pub extern "win64" fn __stdio_common_vsnwprintf_s(
    options: u64,
    out: *mut u16,
    len: usize,
    _max: usize,
    format: *const u16,
    locale: *mut c_void,
    valist: *mut c_void,
) -> i32 {
    __stdio_common_vswprintf(options, out, len, format, locale, valist)
}

pub unsafe extern "win64" fn __stdio_common_vsscanf(
    _options: u64,
    input: *const c_char,
    length: usize,
    format: *const c_char,
    _locale: *mut c_void,
    mut valist: *mut *mut c_void,
) -> i32 {
    if input.is_null() || format.is_null() {
        return -1;
    }
    // Simple parser for standard format strings like "%d.%d.%d.%d" or "%u"
    let in_str = if length == usize::MAX {
        unsafe { std::ffi::CStr::from_ptr(input) }.to_str().unwrap_or("")
    } else {
        let slice = unsafe { std::slice::from_raw_parts(input as *const u8, length) };
        std::str::from_utf8(slice).unwrap_or("")
    };
    let fmt_str = unsafe { std::ffi::CStr::from_ptr(format) }.to_str().unwrap_or("");
    
    let mut in_chars = in_str.chars().peekable();
    let mut fmt_chars = fmt_str.chars().peekable();
    let mut matches = 0;

    while let Some(fc) = fmt_chars.next() {
        if fc == '%' {
            let spec = match fmt_chars.next() {
                Some(s) => s,
                None => break,
            };
            if spec == 'd' || spec == 'u' || spec == 'i' {
                // Skip leading whitespace in input
                while let Some(&ic) = in_chars.peek() {
                    if ic.is_whitespace() { in_chars.next(); } else { break; }
                }
                let mut num_str = String::new();
                while let Some(&ic) = in_chars.peek() {
                    if ic.is_ascii_digit() || (num_str.is_empty() && (ic == '-' || ic == '+')) {
                        num_str.push(ic);
                        in_chars.next();
                    } else {
                        break;
                    }
                }
                if let Ok(val) = num_str.parse::<i32>() {
                    if !valist.is_null() {
                        unsafe {
                            let out_ptr = *valist as *mut i32;
                            if !out_ptr.is_null() {
                                *out_ptr = val;
                            }
                            valist = valist.add(1);
                        }
                    }
                    matches += 1;
                } else {
                    break;
                }
            } else if spec == 's' {
                // String specifier
                while let Some(&ic) = in_chars.peek() {
                    if ic.is_whitespace() { in_chars.next(); } else { break; }
                }
                let mut s_val = Vec::new();
                while let Some(&ic) = in_chars.peek() {
                    if !ic.is_whitespace() {
                        s_val.push(ic as u8);
                        in_chars.next();
                    } else {
                        break;
                    }
                }
                s_val.push(0);
                if !valist.is_null() {
                    unsafe {
                        let out_ptr = *valist as *mut u8;
                        if !out_ptr.is_null() {
                            std::ptr::copy_nonoverlapping(s_val.as_ptr(), out_ptr, s_val.len());
                        }
                        valist = valist.add(1);
                    }
                }
                matches += 1;
            }
        } else if fc.is_whitespace() {
            while let Some(&ic) = in_chars.peek() {
                if ic.is_whitespace() { in_chars.next(); } else { break; }
            }
        } else {
            if in_chars.next() != Some(fc) {
                break;
            }
        }
    }
    matches
}

pub unsafe extern "win64" fn __stdio_common_vswscanf(
    _options: u64,
    input: *const u16,
    length: usize,
    format: *const u16,
    _locale: *mut c_void,
    valist: *mut *mut c_void,
) -> i32 {
    if input.is_null() || format.is_null() {
        return -1;
    }
    let in_str = if length == usize::MAX {
        let len = (0..).take_while(|&i| unsafe { *input.add(i) } != 0).count();
        String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(input, len) })
    } else {
        String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(input, length) })
    };
    let fmt_len = (0..).take_while(|&i| unsafe { *format.add(i) } != 0).count();
    let fmt_str = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(format, fmt_len) });

    let in_c = std::ffi::CString::new(in_str).unwrap();
    let fmt_c = std::ffi::CString::new(fmt_str).unwrap();
    unsafe {
        __stdio_common_vsscanf(0, in_c.as_ptr(), usize::MAX, fmt_c.as_ptr(), std::ptr::null_mut(), valist)
    }
}

// --- Win32 Kernel / Profile / Synch ---

pub extern "win64" fn QueryPerformanceCounter(out: *mut i64) -> i32 {
    if !out.is_null() {
        let elapsed = START_INSTANT.elapsed();
        let ticks = (elapsed.as_nanos() / 100) as i64;
        unsafe { *out = ticks; }
        1
    } else {
        0
    }
}

pub extern "win64" fn QueryPerformanceFrequency(out: *mut i64) -> i32 {
    if !out.is_null() {
        unsafe { *out = 10_000_000; }
        1
    } else {
        0
    }
}

pub extern "win64" fn GetSystemTimeAsFileTime(out: *mut u64) -> () {
    if !out.is_null() {
        let now = std::time::SystemTime::now();
        let dur = now.duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
        let ft = (dur.as_nanos() / 100) as u64 + 116444736000000000u64;
        unsafe { *out = ft; }
    }
}

pub extern "win64" fn GetCurrentProcess() -> *mut c_void {
    (-1isize) as *mut c_void
}

pub extern "win64" fn GetCurrentProcessId() -> u32 {
    std::process::id()
}

pub extern "win64" fn GetCurrentThreadId() -> u32 {
    unsafe { libc::pthread_self() as usize as u32 }
}

pub extern "win64" fn IsDebuggerPresent() -> i32 { 0 }
pub extern "win64" fn IsProcessorFeaturePresent(_feature: u32) -> i32 { 1 }
pub extern "win64" fn InitializeSListHead(head: *mut c_void) {
    if !head.is_null() {
        unsafe { std::ptr::write_bytes(head as *mut u8, 0, 16); }
    }
}

thread_local! {
    static LAST_ERROR: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
}

pub extern "win64" fn GetLastError() -> u32 {
    LAST_ERROR.with(|e| e.get())
}

pub extern "win64" fn SetLastError(err: u32) {
    LAST_ERROR.with(|e| e.set(err));
}

pub extern "win64" fn GetLogicalProcessorInformation(
    buffer: *mut u8,
    returned_length: *mut u32,
) -> i32 {
    if returned_length.is_null() {
        SetLastError(87); // ERROR_INVALID_PARAMETER
        return 0;
    }
    const ENTRY_SIZE: usize = 32;
    const NUM_CORES: usize = 8;
    const REQUIRED_LEN: u32 = (ENTRY_SIZE * NUM_CORES) as u32;

    let cur_len = unsafe { *returned_length };
    if buffer.is_null() || cur_len < REQUIRED_LEN {
        unsafe { *returned_length = REQUIRED_LEN; }
        SetLastError(122); // ERROR_INSUFFICIENT_BUFFER (0x7a)
        return 0;
    }

    unsafe {
        std::ptr::write_bytes(buffer, 0, REQUIRED_LEN as usize);
        for i in 0..NUM_CORES {
            let entry_ptr = buffer.add(i * ENTRY_SIZE);
            (entry_ptr as *mut u64).write(1u64 << i);
            (entry_ptr.add(8) as *mut u32).write(0); // RelationProcessorCore
        }
        *returned_length = REQUIRED_LEN;
    }
    1
}

pub extern "win64" fn GetLogicalProcessorInformationEx(
    _relationship_type: u32,
    _buffer: *mut u8,
    returned_length: *mut u32,
) -> i32 {
    if !returned_length.is_null() {
        unsafe { *returned_length = 0; }
    }
    SetLastError(122);
    0
}

pub extern "win64" fn GetSystemInfo(info: *mut c_void) {
    if info.is_null() { return; }
    unsafe {
        let ptr = info as *mut u8;
        std::ptr::write_bytes(ptr, 0, 48);
        *(ptr as *mut u16) = 9; // PROCESSOR_ARCHITECTURE_AMD64
        *(ptr.add(4) as *mut u32) = 4096;
        *(ptr.add(8) as *mut usize) = 0x10000;
        *(ptr.add(16) as *mut usize) = 0x7fff_ffff_0000;
        *(ptr.add(24) as *mut usize) = 0xff; // 8 cores
        *(ptr.add(32) as *mut u32) = 8;
        *(ptr.add(36) as *mut u32) = 65536;
    }
}

pub extern "win64" fn GetNativeSystemInfo(info: *mut c_void) {
    GetSystemInfo(info);
}

pub extern "win64" fn AcquireSRWLockExclusive(_lock: *mut c_void) {}
pub extern "win64" fn ReleaseSRWLockExclusive(_lock: *mut c_void) {}
pub extern "win64" fn AcquireSRWLockShared(_lock: *mut c_void) {}
pub extern "win64" fn ReleaseSRWLockShared(_lock: *mut c_void) {}
pub extern "win64" fn SleepConditionVariableSRW(_cv: *mut c_void, _lock: *mut c_void, _ms: u32, _flags: u32) -> i32 { 1 }
pub extern "win64" fn SleepConditionVariableCS(_cv: *mut c_void, _cs: *mut c_void, _ms: u32) -> i32 { 1 }
pub extern "win64" fn WakeAllConditionVariable(_cv: *mut c_void) {}
pub extern "win64" fn WakeConditionVariable(_cv: *mut c_void) {}
pub extern "win64" fn InitializeConditionVariable(cv: *mut c_void) {
    if !cv.is_null() {
        unsafe { *(cv as *mut *mut c_void) = std::ptr::null_mut(); }
    }
}
pub extern "win64" fn LocaleNameToLCID(_lp_name: *const u16, _dw_flags: u32) -> u32 {
    1033 // en-US (0x0409)
}
pub extern "win64" fn AddVectoredExceptionHandler(_first: u32, _handler: *mut c_void) -> *mut c_void {
    0x1000 as *mut c_void
}
pub extern "win64" fn RemoveVectoredExceptionHandler(_handle: *mut c_void) -> u32 {
    1
}
pub extern "win64" fn RaiseException(_code: u32, _flags: u32, _n_args: u32, _args: *const usize) {}

pub extern "win64" fn InitializeCriticalSection(cs: *mut c_void) {
    if !cs.is_null() {
        unsafe { std::ptr::write_bytes(cs as *mut u8, 0, 40); }
    }
}
pub extern "win64" fn DeleteCriticalSection(_cs: *mut c_void) {}
pub extern "win64" fn EnterCriticalSection(_cs: *mut c_void) {}
pub extern "win64" fn LeaveCriticalSection(_cs: *mut c_void) {}

// --- Win32 Synchronization Subsystem (Events, Semaphores, Mutexes) ---

#[derive(Debug)]
pub enum SyncKind {
    Event { manual_reset: bool, signaled: bool },
    Semaphore { count: i32, max: i32 },
    Mutex { owner: Option<u32>, recursion: u32 },
}

pub struct SyncObject {
    pub kind: std::sync::Mutex<SyncKind>,
    pub condvar: std::sync::Condvar,
}

static SYNC_OBJECTS: std::sync::LazyLock<std::sync::Mutex<std::collections::HashMap<usize, std::sync::Arc<SyncObject>>>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashMap::new()));
static NEXT_SYNC_HANDLE: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0x4000_0000);

fn alloc_sync_object(kind: SyncKind) -> *mut c_void {
    let handle = NEXT_SYNC_HANDLE.fetch_add(4, std::sync::atomic::Ordering::Relaxed);
    let obj = std::sync::Arc::new(SyncObject {
        kind: std::sync::Mutex::new(kind),
        condvar: std::sync::Condvar::new(),
    });
    SYNC_OBJECTS.lock().unwrap().insert(handle, obj);
    handle as *mut c_void
}

fn get_sync_object(h: *mut c_void) -> Option<std::sync::Arc<SyncObject>> {
    let handle = h as usize;
    SYNC_OBJECTS.lock().unwrap().get(&handle).cloned()
}

fn close_sync_object(handle: usize) -> bool {
    SYNC_OBJECTS.lock().unwrap().remove(&handle).is_some()
}

fn try_acquire_sync(kind: &mut SyncKind, tid: u32) -> bool {
    match kind {
        SyncKind::Event { manual_reset, signaled } => {
            if *signaled {
                if !*manual_reset {
                    *signaled = false;
                }
                true
            } else {
                false
            }
        }
        SyncKind::Semaphore { count, .. } => {
            if *count > 0 {
                *count -= 1;
                true
            } else {
                false
            }
        }
        SyncKind::Mutex { owner, recursion } => {
            if let Some(own) = *owner {
                if own == tid {
                    *recursion += 1;
                    true
                } else {
                    false
                }
            } else {
                *owner = Some(tid);
                *recursion = 1;
                true
            }
        }
    }
}

pub extern "win64" fn CreateEventW(_sa: *mut c_void, manual: i32, initial: i32, _name: *const u16) -> *mut c_void {
    let h = alloc_sync_object(SyncKind::Event {
        manual_reset: manual != 0,
        signaled: initial != 0,
    });
    tracing::debug!(handle = format_args!("{:#x}", h as usize), manual = manual != 0, initial = initial != 0, "CreateEventW");
    h
}

pub extern "win64" fn SetEvent(h: *mut c_void) -> i32 {
    if let Some(obj) = get_sync_object(h) {
        let mut guard = obj.kind.lock().unwrap();
        if let SyncKind::Event { ref mut signaled, .. } = *guard {
            *signaled = true;
            obj.condvar.notify_all();
            return 1;
        }
    }
    1
}

pub extern "win64" fn ResetEvent(h: *mut c_void) -> i32 {
    if let Some(obj) = get_sync_object(h) {
        let mut guard = obj.kind.lock().unwrap();
        if let SyncKind::Event { ref mut signaled, .. } = *guard {
            *signaled = false;
            return 1;
        }
    }
    1
}

pub extern "win64" fn CloseHandle(h: *mut c_void) -> i32 {
    let handle = h as usize;
    if close_sync_object(handle) {
        return 1;
    }
    crate::modules::unix_files::CloseHandle(h)
}

const WAIT_OBJECT_0: u32 = 0;
const WAIT_TIMEOUT: u32 = 0x102;
const INFINITE: u32 = 0xFFFF_FFFF;

pub extern "win64" fn WaitForSingleObject(h: *mut c_void, ms: u32) -> u32 {
    let Some(obj) = get_sync_object(h) else {
        // Untracked handle (thread handle, dummy handle, etc.)
        return 0;
    };

    let tid = GetCurrentThreadId();
    let mut guard = obj.kind.lock().unwrap();

    if try_acquire_sync(&mut *guard, tid) {
        return WAIT_OBJECT_0;
    }

    if ms == 0 {
        return WAIT_TIMEOUT;
    }

    if ms == INFINITE {
        loop {
            guard = obj.condvar.wait(guard).unwrap();
            if try_acquire_sync(&mut *guard, tid) {
                return WAIT_OBJECT_0;
            }
        }
    }

    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(ms as u64);
    loop {
        let now = std::time::Instant::now();
        if now >= deadline {
            return WAIT_TIMEOUT;
        }
        let remaining = deadline - now;
        let (new_guard, timeout_res) = obj.condvar.wait_timeout(guard, remaining).unwrap();
        guard = new_guard;
        if try_acquire_sync(&mut *guard, tid) {
            return WAIT_OBJECT_0;
        }
        if timeout_res.timed_out() {
            return WAIT_TIMEOUT;
        }
    }
}

pub extern "win64" fn GetStartupInfoW(si: *mut c_void) {
    if !si.is_null() {
        unsafe { std::ptr::write_bytes(si as *mut u8, 0, 104); }
    }
}

pub extern "win64" fn MultiByteToWideChar(
    _cp: u32,
    _flags: u32,
    src: *const c_char,
    src_len: i32,
    dst: *mut u16,
    dst_len: i32,
) -> i32 {
    if src.is_null() { return 0; }
    let len = if src_len < 0 {
        let l = unsafe { libc::strlen(src) };
        l + 1
    } else {
        src_len as usize
    };
    if dst_len == 0 {
        return len as i32;
    }
    let copy = len.min(dst_len as usize);
    unsafe {
        for i in 0..copy {
            *dst.add(i) = *src.add(i) as u8 as u16;
        }
    }
    copy as i32
}

pub extern "win64" fn WideCharToMultiByte(
    _cp: u32,
    _flags: u32,
    src: *const u16,
    src_len: i32,
    dst: *mut c_char,
    dst_len: i32,
    _def: *const c_char,
    _used: *mut i32,
) -> i32 {
    if src.is_null() { return 0; }
    let len = if src_len < 0 { wcslen(src) + 1 } else { src_len as usize };
    if dst_len == 0 {
        return len as i32;
    }
    let copy = len.min(dst_len as usize);
    unsafe {
        for i in 0..copy {
            *dst.add(i) = *src.add(i) as u8 as c_char;
        }
    }
    copy as i32
}

pub extern "win64" fn LocalFree(p: *mut c_void) -> *mut c_void {
    free(p);
    std::ptr::null_mut()
}

pub extern "win64" fn BCryptOpenAlgorithmProvider(out: *mut *mut c_void, _id: *const u16, _impl: *const u16, _flags: u32) -> i32 {
    if !out.is_null() {
        unsafe { *out = 1 as *mut c_void; }
    }
    0
}

pub extern "win64" fn BCryptCloseAlgorithmProvider(_h: *mut c_void, _flags: u32) -> i32 { 0 }

pub extern "win64" fn BCryptGenRandom(_h: *mut c_void, buf: *mut u8, count: u32, _flags: u32) -> i32 {
    if !buf.is_null() && count > 0 {
        unsafe { libc::arc4random_buf(buf as *mut libc::c_void, count as usize); }
    }
    0
}

pub extern "win64" fn UnhandledExceptionFilter(_info: *mut c_void) -> i32 { 0 }
pub extern "win64" fn SetUnhandledExceptionFilter(_filter: *mut c_void) -> *mut c_void { std::ptr::null_mut() }
pub extern "win64" fn RtlCaptureContext(_context: *mut c_void) {}
pub extern "win64" fn RtlLookupFunctionEntry(_pc: u64, _image_base: *mut u64, _history: *mut c_void) -> *mut c_void { std::ptr::null_mut() }
pub extern "win64" fn RtlVirtualUnwind(_handler_type: u32, _image_base: u64, _pc: u64, _entry: *mut c_void, _context: *mut c_void, _data: *mut *mut c_void, _establisher: *mut u64, _modifiers: *mut c_void) -> *mut c_void { std::ptr::null_mut() }

pub extern "win64" fn GetCurrentThreadStackLimits(low: *mut usize, high: *mut usize) {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        if !low.is_null() { *low = victory_loader::tls::FAKE_TEB.stack_limit; }
        if !high.is_null() { *high = victory_loader::tls::FAKE_TEB.stack_base; }
    }
}

pub extern "win64" fn Sleep(ms: u32) {
    std::thread::sleep(std::time::Duration::from_millis(ms as u64));
}

pub extern "win64" fn GetTickCount64() -> u64 {
    START_INSTANT.elapsed().as_millis() as u64
}

#[repr(C)]
pub struct MEMORYSTATUSEX {
    pub dwLength: u32,
    pub dwMemoryLoad: u32,
    pub ullTotalPhys: u64,
    pub ullAvailPhys: u64,
    pub ullTotalPageFile: u64,
    pub ullAvailPageFile: u64,
    pub ullTotalVirtual: u64,
    pub ullAvailVirtual: u64,
    pub ullAvailExtendedVirtual: u64,
}

pub unsafe extern "win64" fn GlobalMemoryStatusEx(buf: *mut MEMORYSTATUSEX) -> i32 {
    unsafe {
        if !buf.is_null() {
            let s = &mut *buf;
            s.dwMemoryLoad = 20;
            s.ullTotalPhys = 16 * 1024 * 1024 * 1024;
            s.ullAvailPhys = 12 * 1024 * 1024 * 1024;
            s.ullTotalPageFile = 32 * 1024 * 1024 * 1024;
            s.ullAvailPageFile = 28 * 1024 * 1024 * 1024;
            s.ullTotalVirtual = 0x7fff_ffff_0000;
            s.ullAvailVirtual = 0x7000_0000_0000;
            1
        } else {
            0
        }
    }
}

pub extern "win64" fn VirtualAlloc(addr: *mut c_void, size: usize, _alloc_type: u32, _protect: u32) -> *mut c_void {
    let page_size = 4096;
    let len = size.next_multiple_of(page_size).max(page_size);
    let ptr = unsafe {
        libc::mmap(
            addr,
            len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_ANON | libc::MAP_PRIVATE,
            -1,
            0,
        )
    };
    if ptr == libc::MAP_FAILED {
        std::ptr::null_mut()
    } else {
        ptr
    }
}

pub extern "win64" fn VirtualFree(_addr: *mut c_void, _size: usize, _free_type: u32) -> i32 {
    1
}

pub extern "win64" fn InitializeCriticalSectionAndSpinCount(cs: *mut c_void, _spin: u32) -> i32 {
    InitializeCriticalSection(cs);
    1
}

pub extern "win64" fn CreateMutexA(_attr: *mut c_void, initial: i32, _name: *const c_char) -> *mut c_void {
    let tid = GetCurrentThreadId();
    let (owner, recursion) = if initial != 0 {
        (Some(tid), 1)
    } else {
        (None, 0)
    };
    alloc_sync_object(SyncKind::Mutex { owner, recursion })
}

pub extern "win64" fn ReleaseMutex(h: *mut c_void) -> i32 {
    let tid = GetCurrentThreadId();
    if let Some(obj) = get_sync_object(h) {
        let mut guard = obj.kind.lock().unwrap();
        if let SyncKind::Mutex { ref mut owner, ref mut recursion } = *guard {
            if *owner == Some(tid) {
                if *recursion > 0 {
                    *recursion -= 1;
                    if *recursion == 0 {
                        *owner = None;
                        obj.condvar.notify_one();
                    }
                    return 1;
                }
            }
        }
    }
    1
}

pub extern "win64" fn CreateEventA(_attr: *mut c_void, manual: i32, initial: i32, _name: *const c_char) -> *mut c_void {
    alloc_sync_object(SyncKind::Event {
        manual_reset: manual != 0,
        signaled: initial != 0,
    })
}

pub extern "win64" fn CreateSemaphoreW(_attr: *mut c_void, initial: i32, max: i32, _name: *const u16) -> *mut c_void {
    alloc_sync_object(SyncKind::Semaphore {
        count: initial.max(0),
        max: max.max(1),
    })
}

pub extern "win64" fn CreateSemaphoreExW(_attr: *mut c_void, initial: i32, max: i32, _name: *const u16, _flags: u32, _access: u32) -> *mut c_void {
    alloc_sync_object(SyncKind::Semaphore {
        count: initial.max(0),
        max: max.max(1),
    })
}

pub extern "win64" fn ReleaseSemaphore(h: *mut c_void, count: i32, prev: *mut i32) -> i32 {
    if count <= 0 { return 0; }
    if let Some(obj) = get_sync_object(h) {
        let mut guard = obj.kind.lock().unwrap();
        if let SyncKind::Semaphore { count: ref mut c, max } = *guard {
            if !prev.is_null() {
                unsafe { *prev = *c; }
            }
            *c = (*c + count).min(max);
            obj.condvar.notify_all();
            return 1;
        }
    }
    1
}

pub extern "win64" fn WaitForSingleObjectEx(h: *mut c_void, ms: u32, _alertable: i32) -> u32 {
    WaitForSingleObject(h, ms)
}

pub extern "win64" fn WaitForMultipleObjects(count: u32, handles: *const *mut c_void, wait_all: i32, ms: u32) -> u32 {
    if count == 0 || handles.is_null() {
        return WAIT_TIMEOUT;
    }
    let count = count.min(64) as usize;
    let h_slice = unsafe { std::slice::from_raw_parts(handles, count) };
    let tid = GetCurrentThreadId();

    if wait_all != 0 {
        // Wait for all objects to be signaled
        let deadline = if ms == INFINITE {
            None
        } else {
            Some(std::time::Instant::now() + std::time::Duration::from_millis(ms as u64))
        };

        loop {
            let mut all_signaled = true;
            for &h in h_slice {
                if let Some(obj) = get_sync_object(h) {
                    let mut guard = obj.kind.lock().unwrap();
                    if !try_acquire_sync(&mut *guard, tid) {
                        all_signaled = false;
                        break;
                    }
                }
            }
            if all_signaled {
                return WAIT_OBJECT_0;
            }
            if let Some(dl) = deadline {
                if std::time::Instant::now() >= dl {
                    return WAIT_TIMEOUT;
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    } else {
        // Wait for any object
        let deadline = if ms == INFINITE {
            None
        } else {
            Some(std::time::Instant::now() + std::time::Duration::from_millis(ms as u64))
        };

        loop {
            for (i, &h) in h_slice.iter().enumerate() {
                if let Some(obj) = get_sync_object(h) {
                    let mut guard = obj.kind.lock().unwrap();
                    if try_acquire_sync(&mut *guard, tid) {
                        return WAIT_OBJECT_0 + i as u32;
                    }
                }
            }
            if let Some(dl) = deadline {
                if std::time::Instant::now() >= dl {
                    return WAIT_TIMEOUT;
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    }
}

pub unsafe extern "win64" fn FormatMessageA(
    _flags: u32,
    _source: *const c_void,
    _msg_id: u32,
    _lang_id: u32,
    buffer: *mut c_char,
    size: u32,
    _args: *mut c_void,
) -> u32 {
    unsafe {
        if !buffer.is_null() && size > 10 {
            let s = b"Unknown error\0";
            std::ptr::copy_nonoverlapping(s.as_ptr().cast(), buffer, s.len());
            (s.len() - 1) as u32
        } else {
            0
        }
    }
}

pub extern "win64" fn GetSystemTimePreciseAsFileTime(ft: *mut u64) {
    GetSystemTimeAsFileTime(ft);
}

pub extern "win64" fn FileTimeToSystemTime(_ft: *const u64, _st: *mut c_void) -> i32 { 1 }
pub extern "win64" fn SystemTimeToFileTime(_st: *const c_void, _ft: *mut u64) -> i32 { 1 }

// Windowing stubs
pub extern "win64" fn RegisterClassExA(_wcex: *const c_void) -> u16 { 1 }
pub extern "win64" fn CreateWindowExA(
    _ex_style: u32, _class_name: *const c_char, _window_name: *const c_char,
    _style: u32, _x: i32, _y: i32, _w: i32, _h: i32,
    _parent: *mut c_void, _menu: *mut c_void, _instance: *mut c_void, _param: *mut c_void,
) -> *mut c_void {
    0x10001 as *mut c_void
}
pub extern "win64" fn ShowWindow(_hwnd: *mut c_void, _cmd: i32) -> i32 { 1 }
pub extern "win64" fn DefWindowProcA(_hwnd: *mut c_void, _msg: u32, _wparam: usize, _lparam: isize) -> isize { 0 }
pub extern "win64" fn PeekMessageA(_msg: *mut c_void, _hwnd: *mut c_void, _min: u32, _max: u32, _remove: u32) -> i32 { 0 }
pub extern "win64" fn TranslateMessage(_msg: *const c_void) -> i32 { 0 }
pub extern "win64" fn DispatchMessageA(_msg: *const c_void) -> isize { 0 }

// --- C++ ABI / Exception stubs ---

pub extern "win64" fn __C_specific_handler() -> i32 { 0 }
pub extern "win64" fn _CxxThrowException(_p: *mut c_void, _t: *mut c_void) {
    tracing::error!("_CxxThrowException called on macOS HLE");
}
pub extern "win64" fn __CxxFrameHandler4() -> i32 { 0 }
pub extern "win64" fn __CxxFrameHandler3() -> i32 { 0 }
pub extern "win64" fn __std_terminate() {
    tracing::error!("__std_terminate called on macOS HLE");
}
pub extern "win64" fn __std_exception_copy(_from: *const c_void, _to: *mut c_void) {}
pub extern "win64" fn __std_exception_destroy(_obj: *mut c_void) {}
pub extern "win64" fn __current_exception() -> *mut c_void { std::ptr::null_mut() }
pub extern "win64" fn __current_exception_context() -> *mut c_void { std::ptr::null_mut() }
pub extern "win64" fn __std_type_info_destroy_list(_obj: *mut c_void) {}
pub extern "win64" fn __std_type_info_compare(_a: *const c_void, _b: *const c_void) -> i32 { 0 }
pub extern "win64" fn __RTDynamicCast(_a: *mut c_void, _b: i32, _c: *mut c_void, _d: *mut c_void, _e: i32) -> *mut c_void { _a }
pub extern "win64" fn _purecall() -> i32 { 0 }
pub extern "win64" fn _set_purecall_handler(_h: *mut c_void) -> *mut c_void { std::ptr::null_mut() }
pub extern "win64" fn _Xlength_error(_msg: *const c_char) {}
pub extern "win64" fn _Xbad_function_call() {}

static NEXT_THREAD_ID: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(100);

pub extern "win64" fn CreateThread(
    _lp_thread_attributes: *mut c_void,
    dw_stack_size: usize,
    lp_start_address: usize,
    lp_parameter: usize,
    _dw_creation_flags: u32,
    lp_thread_id: *mut u32,
) -> *mut c_void {
    let tid = NEXT_THREAD_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    if !lp_thread_id.is_null() {
        unsafe { *lp_thread_id = tid; }
    }
    if lp_start_address == 0 {
        return std::ptr::null_mut();
    }
    let stack = if dw_stack_size > 0 { dw_stack_size.max(2 << 20) } else { 2 << 20 };
    let handle = tid as usize as *mut c_void;

    tracing::info!(tid, lp_start_address = format_args!("{:#x}", lp_start_address), "spawning title worker thread via CreateThread");

    let builder = std::thread::Builder::new()
        .name(format!("title-worker-{}", tid))
        .stack_size(stack);

    let res = builder.spawn(move || {
        #[cfg(target_arch = "x86_64")]
        unsafe {
            victory_loader::tls::update_thread_teb();
        }
        type ThreadRoutine = unsafe extern "win64" fn(*mut c_void) -> u32;
        let routine: ThreadRoutine = unsafe { std::mem::transmute(lp_start_address) };
        let ret = unsafe { routine(lp_parameter as *mut c_void) };
        tracing::debug!(tid, ret, "title worker thread finished");
    });

    if res.is_err() {
        tracing::error!(tid, "failed to spawn worker thread");
        return std::ptr::null_mut();
    }

    handle
}

pub extern "win64" fn GetCurrentThread() -> *mut c_void {
    (-2isize) as *mut c_void
}

pub extern "win64" fn ResumeThread(_h: *mut c_void) -> u32 { 1 }
pub extern "win64" fn SuspendThread(_h: *mut c_void) -> u32 { 0 }
pub extern "win64" fn SetThreadPriority(_h: *mut c_void, _prio: i32) -> i32 { 1 }
pub extern "win64" fn GetThreadPriority(_h: *mut c_void) -> i32 { 0 }
pub extern "win64" fn SetThreadDescription(_h: *mut c_void, _desc: *const u16) -> i32 { 0 }
pub extern "win64" fn SetThreadGroupAffinity(_h: *mut c_void, _group: *const c_void, _prev: *mut c_void) -> i32 { 1 }
pub extern "win64" fn SetThreadAffinityMask(_h: *mut c_void, _mask: usize) -> usize { 0xff }
pub extern "win64" fn TerminateThread(_h: *mut c_void, _exit_code: u32) -> i32 { 1 }

#[repr(C)]
pub struct GROUP_AFFINITY {
    pub mask: usize,
    pub group: u16,
    pub reserved: [u16; 3],
}
pub extern "win64" fn GetThreadGroupAffinity(_h: *mut c_void, group: *mut GROUP_AFFINITY) -> i32 {
    if !group.is_null() {
        unsafe {
            (*group).mask = 0xff;
            (*group).group = 0;
            (*group).reserved = [0; 3];
        }
    }
    1
}

pub extern "win64" fn OpenThread(_access: u32, _inherit: i32, thread_id: u32) -> *mut c_void {
    thread_id as usize as *mut c_void
}

#[repr(C)]
pub struct SYSTEMTIME {
    pub wYear: u16,
    pub wMonth: u16,
    pub wDayOfWeek: u16,
    pub wDay: u16,
    pub wHour: u16,
    pub wMinute: u16,
    pub wSecond: u16,
    pub wMilliseconds: u16,
}
pub extern "win64" fn GetLocalTime(st: *mut SYSTEMTIME) {
    if !st.is_null() {
        unsafe {
            let mut tv = libc::timeval { tv_sec: 0, tv_usec: 0 };
            libc::gettimeofday(&mut tv, std::ptr::null_mut());
            let mut tm = libc::tm {
                tm_sec: 0, tm_min: 0, tm_hour: 0, tm_mday: 0,
                tm_mon: 0, tm_year: 0, tm_wday: 0, tm_yday: 0,
                tm_isdst: 0, tm_gmtoff: 0, tm_zone: std::ptr::null_mut(),
            };
            libc::localtime_r(&tv.tv_sec, &mut tm);
            (*st).wYear = (tm.tm_year + 1900) as u16;
            (*st).wMonth = (tm.tm_mon + 1) as u16;
            (*st).wDayOfWeek = tm.tm_wday as u16;
            (*st).wDay = tm.tm_mday as u16;
            (*st).wHour = tm.tm_hour as u16;
            (*st).wMinute = tm.tm_min as u16;
            (*st).wSecond = tm.tm_sec as u16;
            (*st).wMilliseconds = (tv.tv_usec / 1000) as u16;
        }
    }
}
pub extern "win64" fn GetSystemTime(st: *mut SYSTEMTIME) {
    GetLocalTime(st);
}

pub extern "win64" fn RegisterAppStateChangeNotification(
    _routine: *mut c_void,
    _context: *mut c_void,
    registration: *mut *mut c_void,
) -> u32 {
    if !registration.is_null() {
        unsafe { *registration = 1 as *mut c_void; }
    }
    0
}

pub extern "win64" fn RegisterAppConstrainedChangeNotification(
    _routine: *mut c_void,
    _context: *mut c_void,
    registration: *mut *mut c_void,
) -> u32 {
    if !registration.is_null() {
        unsafe { *registration = 2 as *mut c_void; }
    }
    0
}

pub extern "win64" fn UnregisterAppStateChangeNotification(_registration: *mut c_void) -> u32 {
    0
}

pub extern "win64" fn UnregisterAppConstrainedChangeNotification(_registration: *mut c_void) -> u32 {
    0
}

#[repr(C)]
pub struct WSADATA {
    pub wVersion: u16,
    pub wHighVersion: u16,
    pub iMaxSockets: u16,
    pub iMaxUdpDg: u16,
    pub lpVendorInfo: *mut c_char,
    pub szDescription: [c_char; 257],
    pub szSystemStatus: [c_char; 129],
}

pub extern "win64" fn WSAStartup(version: u16, data: *mut WSADATA) -> i32 {
    if !data.is_null() {
        unsafe {
            std::ptr::write_bytes(data as *mut u8, 0, std::mem::size_of::<WSADATA>());
            (*data).wVersion = version;
            (*data).wHighVersion = version;
        }
    }
    0
}

pub extern "win64" fn WSACleanup() -> i32 { 0 }
pub extern "win64" fn WSAGetLastError() -> i32 { 0 }
pub extern "win64" fn WSAIoctl(_s: usize, _code: u32, _in_buf: *mut c_void, _in_len: u32, _out_buf: *mut c_void, _out_len: u32, bytes_returned: *mut u32, _overlapped: *mut c_void, _completion: *mut c_void) -> i32 {
    if !bytes_returned.is_null() {
        unsafe { *bytes_returned = 0; }
    }
    0
}
pub extern "win64" fn ws2_socket(_af: i32, _type: i32, _protocol: i32) -> usize { 1 }
pub extern "win64" fn ws2_closesocket(_s: usize) -> i32 { 0 }
pub extern "win64" fn ws2_bind(_s: usize, _name: *const c_void, _namelen: i32) -> i32 { 0 }
pub extern "win64" fn ws2_connect(_s: usize, _name: *const c_void, _namelen: i32) -> i32 { 0 }
pub extern "win64" fn ws2_listen(_s: usize, _backlog: i32) -> i32 { 0 }
pub extern "win64" fn ws2_accept(_s: usize, _addr: *mut c_void, _addrlen: *mut i32) -> usize { 1 }
pub extern "win64" fn ws2_recv(_s: usize, _buf: *mut c_char, _len: i32, _flags: i32) -> i32 { 0 }
pub extern "win64" fn ws2_recvfrom(_s: usize, _buf: *mut c_char, _len: i32, _flags: i32, _from: *mut c_void, _fromlen: *mut i32) -> i32 { 0 }
pub extern "win64" fn ws2_send(_s: usize, _buf: *const c_char, len: i32, _flags: i32) -> i32 { len }
pub extern "win64" fn ws2_sendto(_s: usize, _buf: *const c_char, len: i32, _flags: i32, _to: *const c_void, _tolen: i32) -> i32 { len }
pub extern "win64" fn ws2_setsockopt(_s: usize, _level: i32, _optname: i32, _optval: *const c_char, _optlen: i32) -> i32 { 0 }
pub extern "win64" fn ws2_shutdown(_s: usize, _how: i32) -> i32 { 0 }
pub extern "win64" fn ws2_getpeername(_s: usize, _name: *mut c_void, _namelen: *mut i32) -> i32 { 0 }
pub extern "win64" fn ws2_getsockname(_s: usize, _name: *mut c_void, _namelen: *mut i32) -> i32 { 0 }
pub extern "win64" fn ws2_gethostbyname(_name: *const c_char) -> *mut c_void { std::ptr::null_mut() }
pub extern "win64" fn ws2_getprotobyname(_name: *const c_char) -> *mut c_void { std::ptr::null_mut() }
pub extern "win64" fn ws2_getservbyname(_name: *const c_char, _proto: *const c_char) -> *mut c_void { std::ptr::null_mut() }
pub extern "win64" fn ws2_getservbyport(_port: i32, _proto: *const c_char) -> *mut c_void { std::ptr::null_mut() }
pub extern "win64" fn ws2_inet_addr(_cp: *const c_char) -> u32 { 0x0100007f } // 127.0.0.1
pub extern "win64" fn ws2_select(_nfds: i32, _readfds: *mut c_void, _writefds: *mut c_void, _exceptfds: *mut c_void, _timeout: *const c_void) -> i32 { 0 }
pub extern "win64" fn ws2_getaddrinfo(_nodename: *const c_char, _servname: *const c_char, _hints: *const c_void, res: *mut *mut c_void) -> i32 {
    if !res.is_null() {
        unsafe { *res = std::ptr::null_mut(); }
    }
    0
}
pub extern "win64" fn ws2_freeaddrinfo(_res: *mut c_void) {}

pub extern "win64" fn CoInitializeEx(_pv: *mut c_void, _coinit: u32) -> i32 { 0 }
pub extern "win64" fn CoUninitialize() {}
pub extern "win64" fn CoCreateGuid(guid: *mut u8) -> i32 {
    if !guid.is_null() {
        unsafe { libc::arc4random_buf(guid as *mut libc::c_void, 16); }
    }
    0
}
pub extern "win64" fn CoTaskMemFree(_pv: *mut c_void) {}
pub extern "win64" fn CoCreateInstance(_rclsid: *const c_void, _punk: *mut c_void, _ctx: u32, _riid: *const c_void, ppv: *mut *mut c_void) -> i32 {
    if !ppv.is_null() {
        unsafe { *ppv = std::ptr::null_mut(); }
    }
    0x80004002u32 as i32 // E_NOINTERFACE
}
pub extern "win64" fn PropVariantClear(_pvar: *mut c_void) -> i32 { 0 }
pub extern "win64" fn StringFromGUID2(_rguid: *const c_void, lpsz: *mut u16, cch_max: i32) -> i32 {
    if !lpsz.is_null() && cch_max > 0 {
        unsafe { *lpsz = 0; }
    }
    0
}
pub extern "win64" fn MoveFileExW(_old: *const u16, _new: *const u16, _flags: u32) -> i32 { 1 }
pub extern "win64" fn lstrcmpW(s1: *const u16, s2: *const u16) -> i32 {
    if s1.is_null() && s2.is_null() { return 0; }
    if s1.is_null() { return -1; }
    if s2.is_null() { return 1; }
    let mut i = 0;
    loop {
        let c1 = unsafe { *s1.add(i) };
        let c2 = unsafe { *s2.add(i) };
        if c1 != c2 {
            return (c1 as i32) - (c2 as i32);
        }
        if c1 == 0 {
            return 0;
        }
        i += 1;
    }
}
pub extern "win64" fn SetNamedPipeHandleState(_h: *mut c_void, _mode: *mut u32, _max_col: *mut u32, _collect_timeout: *mut u32) -> i32 { 1 }
pub extern "win64" fn WaitNamedPipeW(_name: *const u16, _timeout: u32) -> i32 { 1 }
pub extern "win64" fn GetDateFormatEx(_locale: *const u16, _flags: u32, _date: *const c_void, _format: *const u16, _out: *mut u16, _out_size: i32, _reserved: *const c_void) -> i32 { 0 }
pub extern "win64" fn GetTimeFormatEx(_locale: *const u16, _flags: u32, _time: *const c_void, _format: *const u16, _out: *mut u16, _out_size: i32) -> i32 { 0 }
pub extern "win64" fn SetProcessPriorityBoost(_h_process: *mut c_void, _disable_priority_boost: i32) -> i32 { 1 }
pub extern "win64" fn GetUserDefaultGeoName(_geo_name: *mut u16, _geo_name_count: i32) -> i32 { 0 }
pub extern "win64" fn SetThreadIdealProcessorEx(_h_thread: *mut c_void, _ideal_processor: *const c_void, _previous_ideal_processor: *mut c_void) -> i32 { 1 }

use crate::modules::xgameruntime::{Methods, Object};

// DirectStorage Factory & Objects for macOS
static DSTORAGE_FACTORY_VTABLE: Methods<16> = Methods([
    dstorage_stub as *const (), // 0x00 QueryInterface
    dstorage_addref as *const (), // 0x08 AddRef
    dstorage_release as *const (), // 0x10 Release
    dstorage_stub as *const (), // 0x18
    dstorage_open_file as *const (), // 0x20 OpenFile
    dstorage_create_status_array as *const (), // 0x28 CreateStatusArray
    dstorage_stub as *const (), // 0x30
    dstorage_stub as *const (), // 0x38
    dstorage_set_staging_buffer_size as *const (), // 0x40 SetStagingBufferSize
    dstorage_stub as *const (), // 0x48
    dstorage_create_queue as *const (), // 0x50 CreateQueue
    dstorage_stub as *const (), // 0x58
    dstorage_stub as *const (), // 0x60
    dstorage_stub as *const (), // 0x68
    dstorage_stub as *const (), // 0x70
    dstorage_stub as *const (), // 0x78
]);

static DSTORAGE_QUEUE_VTABLE: Methods<16> = Methods([
    dstorage_stub as *const (), // 0x00
    dstorage_addref as *const (), // 0x08
    dstorage_release as *const (), // 0x10
    dstorage_stub as *const (), // 0x18 EnqueueRequest
    dstorage_stub as *const (), // 0x20 EnqueueStatus
    dstorage_stub as *const (), // 0x28 EnqueueSignal
    dstorage_stub as *const (), // 0x30 Submit
    dstorage_stub as *const (), // 0x38 CancelRequestsWithTag
    dstorage_stub as *const (), // 0x40 Close
    dstorage_stub as *const (), // 0x48
    dstorage_stub as *const (), // 0x50
    dstorage_stub as *const (), // 0x58
    dstorage_stub as *const (), // 0x60
    dstorage_stub as *const (), // 0x68
    dstorage_stub as *const (), // 0x70
    dstorage_stub as *const (), // 0x78
]);

static DSTORAGE_STATUS_VTABLE: Methods<16> = Methods([
    dstorage_stub as *const (), // 0x00
    dstorage_addref as *const (), // 0x08
    dstorage_release as *const (), // 0x10
    dstorage_is_complete as *const (), // 0x18 IsComplete
    dstorage_stub as *const (), // 0x20 GetStatus
    dstorage_stub as *const (), // 0x28
    dstorage_stub as *const (), // 0x30
    dstorage_stub as *const (), // 0x38
    dstorage_stub as *const (), // 0x40
    dstorage_stub as *const (), // 0x48
    dstorage_stub as *const (), // 0x50
    dstorage_stub as *const (), // 0x58
    dstorage_stub as *const (), // 0x60
    dstorage_stub as *const (), // 0x68
    dstorage_stub as *const (), // 0x70
    dstorage_stub as *const (), // 0x78
]);

static DSTORAGE_FACTORY: Object = Object::new("dstorage factory", &DSTORAGE_FACTORY_VTABLE);
static DSTORAGE_QUEUE: Object = Object::new("dstorage queue", &DSTORAGE_QUEUE_VTABLE);
static DSTORAGE_STATUS: Object = Object::new("dstorage status array", &DSTORAGE_STATUS_VTABLE);

extern "win64" fn dstorage_stub() -> u64 { 0 }
extern "win64" fn dstorage_addref() -> u32 { 2 }
extern "win64" fn dstorage_release() -> u32 { 1 }
extern "win64" fn dstorage_is_complete() -> u32 { 1 } // Always reports complete
extern "win64" fn dstorage_set_staging_buffer_size(_this: *mut c_void, size: u32) -> i32 {
    eprintln!("dstorage: SetStagingBufferSize {size} bytes");
    0 // S_OK
}
extern "win64" fn dstorage_create_status_array(_this: *mut c_void, _capacity: u32, _name: *const c_char, _iid: *const c_void, out: *mut *mut c_void) -> i32 {
    if !out.is_null() {
        unsafe { *out = std::ptr::from_ref(&DSTORAGE_STATUS).cast_mut().cast(); }
    }
    0 // S_OK
}
extern "win64" fn dstorage_create_queue(_this: *mut c_void, _desc: *const c_void, _iid: *const c_void, out: *mut *mut c_void) -> i32 {
    if !out.is_null() {
        unsafe { *out = std::ptr::from_ref(&DSTORAGE_QUEUE).cast_mut().cast(); }
    }
    0 // S_OK
}
extern "win64" fn dstorage_open_file(_this: *mut c_void, _path: *const u16, _iid: *const c_void, out: *mut *mut c_void) -> i32 {
    if !out.is_null() {
        unsafe { *out = std::ptr::from_ref(&DSTORAGE_QUEUE).cast_mut().cast(); }
    }
    0 // S_OK
}
pub extern "win64" fn _Random_device() -> u32 {
    use std::time::SystemTime;
    SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).map_or(42, |d| d.subsec_nanos())
}

// C++ std::basic_streambuf, basic_iostream, and std::locale MSVC HLE emulation

#[repr(C)]
pub struct Locimp {
    pub vtable: *const (),
    pub refs: usize,
    pub facet_ptr: *const *const usize,
    pub facet_cnt: usize,
    pub catmask: i32,
    pub xparent: u8,
    pub _pad: [u8; 3],
}

unsafe impl Sync for Locimp {}

static LOCIMP_VTABLE: Methods<8> = Methods([
    dstorage_stub as *const (), // 0x00
    dstorage_stub as *const (), // 0x08
    locimp_decref as *const (), // 0x10 _Decref
    dstorage_stub as *const (), // 0x18
    dstorage_stub as *const (), // 0x20
    dstorage_stub as *const (), // 0x28
    dstorage_stub as *const (), // 0x30
    dstorage_stub as *const (), // 0x38
]);

static FACET_VTABLE: Methods<8> = Methods([
    dstorage_stub as *const (),
    dstorage_stub as *const (),
    dstorage_stub as *const (),
    dstorage_stub as *const (),
    dstorage_stub as *const (),
    dstorage_stub as *const (),
    dstorage_stub as *const (),
    dstorage_stub as *const (),
]);

static DUMMY_FACET: Methods<8> = Methods([
    FACET_VTABLE.0.as_ptr() as *const (),
    std::ptr::null(),
    std::ptr::null(),
    std::ptr::null(),
    std::ptr::null(),
    std::ptr::null(),
    std::ptr::null(),
    std::ptr::null(),
]);

static mut FACET_ARRAY: [*const usize; 64] = [std::ptr::null(); 64];

static mut GLOBAL_LOCIMP: Locimp = Locimp {
    vtable: std::ptr::null(),
    refs: 1,
    facet_ptr: std::ptr::null(),
    facet_cnt: 64,
    catmask: 0,
    xparent: 0,
    _pad: [0; 3],
};

#[repr(C)]
pub struct Locale {
    pub _pad: usize,
    pub ptr: *mut Locimp,
}

static mut CLASSIC_LOCALE: Locale = Locale {
    _pad: 0,
    ptr: std::ptr::null_mut(),
};

extern "win64" fn locimp_decref(_this: *mut c_void) -> *mut c_void {
    std::ptr::null_mut()
}

pub extern "win64" fn ios_base_getloc(_this: *const c_void, ret: *mut [usize; 2]) -> *mut [usize; 2] {
    init_locale_subsystem();
    if !ret.is_null() {
        unsafe {
            (*ret)[0] = 0;
            (*ret)[1] = std::ptr::addr_of_mut!(GLOBAL_LOCIMP) as usize;
        }
    }
    ret
}

pub extern "win64" fn locale_classic() -> *const Locale {
    init_locale_subsystem();
    unsafe { std::ptr::addr_of!(CLASSIC_LOCALE) }
}

pub extern "win64" fn locale_getgloballocale() -> *mut Locimp {
    init_locale_subsystem();
    unsafe { std::ptr::addr_of_mut!(GLOBAL_LOCIMP) }
}

pub extern "win64" fn locale_init(_b: bool) -> *mut Locimp {
    init_locale_subsystem();
    unsafe { std::ptr::addr_of_mut!(GLOBAL_LOCIMP) }
}

fn init_locale_subsystem() {
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| unsafe {
        GLOBAL_LOCIMP.vtable = LOCIMP_VTABLE.0.as_ptr() as *const ();
        let facet_ptr = std::ptr::addr_of_mut!(FACET_ARRAY).cast::<*const usize>();
        for i in 0..64 {
            *facet_ptr.add(i) = DUMMY_FACET.0.as_ptr() as *const usize;
        }
        GLOBAL_LOCIMP.facet_ptr = facet_ptr as *const *const usize;
        CLASSIC_LOCALE.ptr = std::ptr::addr_of_mut!(GLOBAL_LOCIMP);
    });
}

static CTYPE_W_ID: usize = 1;
static CODECVT_ID: usize = 2;
static ID_CNT: i32 = 10;

pub extern "win64" fn facet_getcat(ppfacet: *mut *const (), _ploc: *const c_void) -> usize {
    init_locale_subsystem();
    if !ppfacet.is_null() {
        unsafe {
            *ppfacet = DUMMY_FACET.0.as_ptr() as *const ();
        }
    }
    1
}

pub extern "win64" fn locimp_new(_transparent: bool) -> *mut Locimp {
    init_locale_subsystem();
    unsafe { std::ptr::addr_of_mut!(GLOBAL_LOCIMP) }
}

pub extern "win64" fn locimp_makeloc(_locinfo: *const c_void, _cat: i32, _pimp: *mut Locimp, _ploc: *const c_void) -> *mut Locimp {
    init_locale_subsystem();
    unsafe { std::ptr::addr_of_mut!(GLOBAL_LOCIMP) }
}

pub extern "win64" fn locale_id_cast(_this: *const c_void) -> usize {
    1
}

pub extern "win64" fn ostream_osfx(_this: *mut c_void) {}

pub extern "win64" fn istream_ipfx(_this: *mut c_void, _noskip: bool) -> bool {
    true
}

pub extern "win64" fn locinfo_ctor(this: *mut c_void, _cat: i32, _locname: *const c_char) -> *mut c_void {
    this
}

pub extern "win64" fn locinfo_dtor(this: *mut c_void) -> *mut c_void {
    this
}

pub extern "win64" fn yarn_assign(this: *mut c_void, _rhs: *const c_char) -> *mut c_void {
    this
}

pub extern "win64" fn streambuf_pninc(this: *mut u8) -> *mut u8 {
    if !this.is_null() {
        unsafe {
            let pnext_ptr = *(this.add(0x40) as *mut *mut *mut u8); // _IPnext
            if !pnext_ptr.is_null() {
                let cur = *pnext_ptr;
                if !cur.is_null() {
                    *pnext_ptr = cur.add(2); // advance wchar
                    return cur;
                }
            }
        }
    }
    std::ptr::null_mut()
}

pub extern "win64" fn streambuf_gninc(this: *mut u8) -> *mut u8 {
    if !this.is_null() {
        unsafe {
            let gnext_ptr = *(this.add(0x38) as *mut *mut *mut u8); // _IGnext
            if !gnext_ptr.is_null() {
                let cur = *gnext_ptr;
                if !cur.is_null() {
                    *gnext_ptr = cur.add(2);
                    return cur;
                }
            }
        }
    }
    std::ptr::null_mut()
}

pub extern "win64" fn basic_ios_setstate(this: *mut u8, state: i32, _reraise: bool) {
    if !this.is_null() {
        unsafe {
            let cur = *(this.add(0x10) as *mut i32);
            *(this.add(0x10) as *mut i32) = cur | state;
        }
    }
}

pub extern "win64" fn basic_ios_clear(this: *mut u8, state: i32, _reraise: bool) {
    if !this.is_null() {
        unsafe {
            *(this.add(0x10) as *mut i32) = state;
        }
    }
}

pub extern "win64" fn ios_base_good(this: *const u8) -> bool {
    if !this.is_null() {
        unsafe { *(this.add(0x10) as *const i32) == 0 }
    } else {
        false
    }
}

pub extern "win64" fn ios_base_fail(this: *const u8) -> bool {
    if !this.is_null() {
        unsafe { (*(this.add(0x10) as *const i32) & 6) != 0 }
    } else {
        true
    }
}

pub extern "win64" fn basic_ios_init(this: *mut u8, sb: *mut c_void, _isstd: bool) {
    if !this.is_null() {
        unsafe {
            std::ptr::write_bytes(this.add(8), 0, 120);
            *(this.add(0x10) as *mut i32) = 0;
            *(this.add(0x18) as *mut i32) = 0x201;
            *(this.add(0x20) as *mut i64) = 6;
            *(this.add(0x40) as *mut *mut Locimp) = std::ptr::addr_of_mut!(GLOBAL_LOCIMP);
            *(this.add(0x48) as *mut *mut c_void) = sb;
            *(this.add(0x58) as *mut u16) = 0x20;
        }
    }
}

pub extern "win64" fn basic_streambuf_xsputn(_this: *mut c_void, _s: *const c_void, count: i64) -> i64 {
    count
}

pub extern "win64" fn basic_streambuf_xsgetn(_this: *mut c_void, _s: *mut c_void, _count: i64) -> i64 {
    0
}

pub extern "win64" fn basic_streambuf_sync(_this: *mut c_void) -> i32 {
    0
}

pub extern "win64" fn basic_streambuf_showmanyc(_this: *mut c_void) -> i64 {
    0
}

pub extern "win64" fn basic_streambuf_uflow(_this: *mut c_void) -> i32 {
    -1 // EOF
}

pub extern "win64" fn basic_streambuf_sbumpc(_this: *mut c_void) -> i32 {
    -1 // EOF
}

pub extern "win64" fn basic_streambuf_setbuf(this: *mut c_void, _buf: *mut c_void, _count: i64) -> *mut c_void {
    this
}

pub extern "win64" fn basic_ostream_write(this: *mut c_void, _s: *const c_void, _count: i64) -> *mut c_void {
    this
}

pub extern "win64" fn basic_istream_read(this: *mut c_void, _s: *mut c_void, _count: i64) -> *mut c_void {
    this
}

pub extern "win64" fn basic_istream_seekg(this: *mut c_void, _pos: i64, _dir: i32) -> *mut c_void {
    this
}

pub extern "win64" fn std_uncaught_exception() -> bool {
    false
}

pub extern "win64" fn ios_base_dtor_static(_this: *mut c_void) {}

pub extern "win64" fn lockit_ctor(this: *mut c_void, _kind: i32) -> *mut c_void {
    this
}

pub extern "win64" fn lockit_dtor(this: *mut c_void) -> *mut c_void {
    this
}

pub extern "win64" fn ctype_widen(_this: *const c_void, c: u8) -> u16 {
    c as u16
}

pub extern "win64" fn sputc_w(_this: *mut c_void, c: u16) -> u16 {
    c
}

pub extern "win64" fn sputc_d(_this: *mut c_void, c: u8) -> i32 {
    c as i32
}

pub extern "win64" fn ostream_flush(this: *mut c_void) -> *mut c_void {
    this
}

pub extern "win64" fn streambuf_lock(_this: *mut c_void) {}
pub extern "win64" fn streambuf_unlock(_this: *mut c_void) {}

pub extern "win64" fn stream_dtor_noop(this: *mut c_void) -> *mut c_void {
    this
}

static STREAMBUF_VTABLE: Methods<16> = Methods([
    stream_dtor_noop as *const (), // 0x00 dtor
    streambuf_lock as *const (),   // 0x08 _Lock
    streambuf_unlock as *const (), // 0x10 _Unlock
    dstorage_stub as *const (),    // 0x18 overflow
    dstorage_stub as *const (),    // 0x20 pbackfail
    dstorage_stub as *const (),    // 0x28 showmanyc
    dstorage_stub as *const (),    // 0x30 underflow
    dstorage_stub as *const (),    // 0x38 uflow
    dstorage_stub as *const (),    // 0x40 xsgetn
    dstorage_stub as *const (),    // 0x48 xsputn
    dstorage_stub as *const (),    // 0x50 seekoff
    dstorage_stub as *const (),    // 0x58 seekpos
    dstorage_stub as *const (),    // 0x60 setbuf
    dstorage_stub as *const (),    // 0x68 sync
    dstorage_stub as *const (),    // 0x70 imbue
    dstorage_stub as *const (),    // 0x78
]);

pub extern "win64" fn basic_streambuf_ctor(this: *mut u8) -> *mut u8 {
    init_locale_subsystem();
    if !this.is_null() {
        unsafe {
            std::ptr::write_bytes(this, 0, 128);
            *(this as *mut usize) = STREAMBUF_VTABLE.0.as_ptr() as usize;

            let gfirst_ptr = this.add(0x08) as *mut usize;
            let pfirst_ptr = this.add(0x10) as *mut usize;
            let gnext_ptr  = this.add(0x28) as *mut usize;
            let pnext_ptr  = this.add(0x30) as *mut usize;
            let gcount_ptr = this.add(0x48) as *mut i32;
            let pcount_ptr = this.add(0x4c) as *mut i32;

            *(this.add(0x18) as *mut *mut usize) = gfirst_ptr; // _IGfirst
            *(this.add(0x20) as *mut *mut usize) = pfirst_ptr; // _IPfirst
            *(this.add(0x38) as *mut *mut usize) = gnext_ptr;  // _IGnext
            *(this.add(0x40) as *mut *mut usize) = pnext_ptr;  // _IPnext
            *(this.add(0x50) as *mut *mut i32)   = gcount_ptr; // _IGcount
            *(this.add(0x58) as *mut *mut i32)   = pcount_ptr; // _IPcount

            *(this.add(0x60) as *mut usize) = 0;
            *(this.add(0x68) as *mut *mut Locimp) = std::ptr::addr_of_mut!(GLOBAL_LOCIMP);
            *(this.add(0x70) as *mut u32) = 0;
        }
    }
    this
}

pub extern "win64" fn basic_iostream_ctor(this: *mut u8, sb: *mut c_void) -> *mut u8 {
    init_locale_subsystem();
    if !this.is_null() {
        unsafe {
            let vbtable_ptr = *(this as *const *const i32);
            let ios_offset = if !vbtable_ptr.is_null() {
                *vbtable_ptr.add(1) as isize
            } else {
                0x98
            };
            let ios = this.offset(ios_offset);

            std::ptr::write_bytes(ios.add(8), 0, 120);

            *(ios.add(0x10) as *mut i32) = 0; // _State = goodbit
            *(ios.add(0x14) as *mut i32) = 0; // _Except = 0
            *(ios.add(0x18) as *mut i32) = 0x201; // _Fmtfl = skipws | dec
            *(ios.add(0x20) as *mut i64) = 6; // _Prec = 6
            *(ios.add(0x28) as *mut i64) = 0; // _Wide = 0
            *(ios.add(0x40) as *mut *mut Locimp) = std::ptr::addr_of_mut!(GLOBAL_LOCIMP);
            *(ios.add(0x48) as *mut *mut c_void) = sb; // _Mystrbuf = sb
            *(ios.add(0x50) as *mut *mut c_void) = std::ptr::null_mut(); // _Mytie = null
            *(ios.add(0x58) as *mut u16) = 0x20; // _Fill = ' '
        }
    }
    this
}

pub extern "win64" fn basic_ios_ctor(this: *mut u8) -> *mut u8 {
    init_locale_subsystem();
    if !this.is_null() {
        unsafe {
            std::ptr::write_bytes(this.add(8), 0, 120);
            *(this.add(0x10) as *mut i32) = 0;
            *(this.add(0x18) as *mut i32) = 0x201;
            *(this.add(0x20) as *mut i64) = 6;
            *(this.add(0x40) as *mut *mut Locimp) = std::ptr::addr_of_mut!(GLOBAL_LOCIMP);
            *(this.add(0x58) as *mut u16) = 0x20;
        }
    }
    this
}

pub extern "win64" fn ios_base_ctor(this: *mut u8) -> *mut u8 {
    init_locale_subsystem();
    if !this.is_null() {
        unsafe {
            std::ptr::write_bytes(this.add(8), 0, 64);
            *(this.add(0x10) as *mut i32) = 0;
            *(this.add(0x18) as *mut i32) = 0x201;
            *(this.add(0x20) as *mut i64) = 6;
            *(this.add(0x40) as *mut *mut Locimp) = std::ptr::addr_of_mut!(GLOBAL_LOCIMP);
        }
    }
    this
}

pub extern "win64" fn _Mtx_init_in_situ(_mtx: *mut c_void, _type: i32) -> i32 {
    0 // _Thrd_success
}

pub extern "win64" fn _Mtx_destroy_in_situ(_mtx: *mut c_void) {}

pub extern "win64" fn _Mtx_lock(_mtx: *mut c_void) -> i32 {
    0 // _Thrd_success
}

pub extern "win64" fn _Mtx_unlock(_mtx: *mut c_void) -> i32 {
    0 // _Thrd_success
}

pub extern "win64" fn _Query_perf_counter(qpc: *mut i64) -> i32 {
    if !qpc.is_null() {
        unsafe {
            *qpc = START_INSTANT.elapsed().as_nanos() as i64;
        }
    }
    1
}

pub extern "win64" fn _Query_perf_frequency(qpf: *mut i64) -> i32 {
    if !qpf.is_null() {
        unsafe {
            *qpf = 1_000_000_000;
        }
    }
    1
}

pub extern "win64" fn _Xtime_get_ticks() -> i64 {
    START_INSTANT.elapsed().as_nanos() as i64
}

pub extern "win64" fn DStorageGetFactory(_iid: *const c_void, out: *mut *mut c_void) -> i32 {
    eprintln!("dstorage: DStorageGetFactory called");
    if !out.is_null() {
        unsafe { *out = std::ptr::from_ref(&DSTORAGE_FACTORY).cast_mut().cast(); }
    }
    0 // S_OK
}

extern "win64" fn dummy_vtable_method() -> u64 {
    0
}

struct DummyVtable<const N: usize>([*const (); N]);
unsafe impl<const N: usize> Sync for DummyVtable<N> {}

static DUMMY_CPP_VTABLE: DummyVtable<64> = DummyVtable([dummy_vtable_method as *const (); 64]);

extern "win64" fn dummy_cpp_ctor(this: *mut c_void) -> *mut c_void {
    this
}

extern "win64" fn dummy_cpp_dtor(_this: *mut c_void) {}

pub(crate) fn module() -> HleModule {
    HleModule {
        name: "unix_crt",
        dlls: &[
            "api-ms-win-crt-*",
            "vcruntime140*",
            "msvcp140*",
            "api-ms-win-core-*",
            "ext-ms-win-rtcore-ntuser-*",
            "kernel32.dll",
            "user32.dll",
            "advapi32.dll",
            "bcrypt.dll",
            "ws2_32.dll",
            "WS2_32.dll",
            "ole32.dll",
            "xcrdapi.dll",
            "XCRDAPI.dll",
        ],
        exports: vec![
            HleExport {
                name: "??_7ios_base@std@@6B@",
                address: DUMMY_CPP_VTABLE.0.as_ptr() as usize,
            },
            HleExport {
                name: "??_7?$basic_ios@DU?$char_traits@D@std@@@std@@6B@",
                address: DUMMY_CPP_VTABLE.0.as_ptr() as usize,
            },
            HleExport {
                name: "??_7?$basic_ios@_WU?$char_traits@_W@std@@@std@@6B@",
                address: DUMMY_CPP_VTABLE.0.as_ptr() as usize,
            },
            HleExport {
                name: "??0?$basic_istream@DU?$char_traits@D@std@@@std@@QEAA@PEAV?$basic_streambuf@DU?$char_traits@D@std@@@1@_N@Z",
                address: dummy_cpp_ctor as *const () as usize,
            },
            HleExport {
                name: "??0?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAA@PEAV?$basic_streambuf@DU?$char_traits@D@std@@@1@_N@Z",
                address: dummy_cpp_ctor as *const () as usize,
            },
            HleExport {
                name: "??1?$basic_istream@DU?$char_traits@D@std@@@std@@UEAA@XZ",
                address: dummy_cpp_dtor as *const () as usize,
            },
            HleExport {
                name: "??1?$basic_ostream@DU?$char_traits@D@std@@@std@@UEAA@XZ",
                address: dummy_cpp_dtor as *const () as usize,
            },
            HleExport {
                name: "?_Init@?$basic_streambuf@DU?$char_traits@D@std@@@std@@IEAAXXZ",
                address: dummy_cpp_dtor as *const () as usize,
            },
            hle_export!(malloc),
            hle_export!(free),
            hle_export!(calloc),
            hle_export!(realloc),
            hle_export!(_callnewh),
            hle_export!(_set_new_mode),
            hle_export!(memcpy),
            hle_export!(memmove),
            hle_export!(memset),
            hle_export!(memcmp),
            hle_export!(memchr),
            hle_export!(strlen),
            hle_export!(strcmp),
            hle_export!(strncmp),
            hle_export!(strcpy),
            hle_export!(strcpy_s),
            hle_export!(strncpy),
            hle_export!(strncpy_s),
            hle_export!(strcat),
            hle_export!(strncat),
            hle_export!(strcat_s),
            hle_export!(strchr),
            hle_export!(strrchr),
            hle_export!(strstr),
            hle_export!(strcspn),
            hle_export!(strpbrk),
            hle_export!(strtok),
            hle_export!(strtok_s),
            hle_export!(tolower),
            hle_export!(toupper),
            hle_export!(isalnum),
            hle_export!(isalpha),
            hle_export!(isdigit),
            hle_export!(islower),
            hle_export!(isspace),
            hle_export!(isxdigit),
            hle_export!(_stricmp),
            hle_export!(_strnicmp),
            hle_export!(wcslen),
            hle_export!(wcscmp),
            hle_export!(wcsncpy),
            hle_export!(wcscat_s),
            hle_export!(wcscoll),
            hle_export!(_wcsicoll),
            hle_export!(_wcsnicmp),
            hle_export!(wcsrchr),
            hle_export!(wcstok_s),
            hle_export!(sin),
            hle_export!(sinf),
            hle_export!(cos),
            hle_export!(cosf),
            hle_export!(tan),
            hle_export!(tanf),
            hle_export!(asin),
            hle_export!(asinf),
            hle_export!(acos),
            hle_export!(acosf),
            hle_export!(sinhf),
            hle_export!(atan),
            hle_export!(atanf),
            hle_export!(atan2),
            hle_export!(atan2f),
            hle_export!(exp),
            hle_export!(expf),
            hle_export!(exp2),
            hle_export!(exp2f),
            hle_export!(log),
            hle_export!(logf),
            hle_export!(log2),
            hle_export!(log2f),
            hle_export!(log10f),
            hle_export!(pow),
            hle_export!(powf),
            hle_export!(cbrtf),
            hle_export!(ceilf),
            hle_export!(fmod),
            hle_export!(fmodf),
            hle_export!(modf),
            hle_export!(modff),
            HleExport { name: "remainderf", address: remainderf_fn as *const () as usize },
            HleExport { name: "nextafterf", address: nextafterf_fn as *const () as usize },
            hle_export!(nexttowardf),
            hle_export!(lroundf),
            HleExport { name: "erff", address: erff_fn as *const () as usize },
            hle_export!(_isnan),
            hle_export!(_dtest),
            hle_export!(_fdtest),
            hle_export!(_fdsign),
            hle_export!(__setusermatherr),
            hle_export!(atoi),
            hle_export!(atof),
            hle_export!(atoll),
            hle_export!(strtod),
            hle_export!(strtof),
            hle_export!(strtol),
            hle_export!(strtoll),
            hle_export!(strtoul),
            hle_export!(strtoull),
            hle_export!(_itoa),
            hle_export!(_strtoi64),
            hle_export!(_strtoui64),
            hle_export!(_wtoi),
            hle_export!(wcstoull),
            hle_export!(wcstombs),
            hle_export!(GetUserDefaultLocaleName),
            hle_export!(GetUserDefaultLCID),
            hle_export!(GetSystemDefaultLCID),
            hle_export!(qsort),
            hle_export!(bsearch),
            hle_export!(rand),
            hle_export!(srand),
            hle_export!(_initterm),
            hle_export!(_initterm_e),
            hle_export!(_configure_narrow_argv),
            hle_export!(_initialize_narrow_environment),
            hle_export!(_initialize_onexit_table),
            hle_export!(_register_onexit_function),
            hle_export!(_execute_onexit_table),
            hle_export!(_crt_atexit),
            hle_export!(_crt_at_quick_exit),
            hle_export!(_register_thread_local_exe_atexit_callback),
            hle_export!(_seh_filter_dll),
            hle_export!(_seh_filter_exe),
            hle_export!(_set_app_type),
            hle_export!(_get_narrow_winmain_command_line),
            hle_export!(_cexit),
            hle_export!(_c_exit),
            hle_export!(_exit),
            hle_export!(_invalid_parameter_noinfo),
            hle_export!(_set_invalid_parameter_handler),
            hle_export!(_invoke_watson),
            hle_export!(_wassert),
            hle_export!(_configthreadlocale),
            hle_export!(localeconv),
            hle_export!(_errno),
            hle_export!(_get_errno),
            hle_export!(_set_errno),
            hle_export!(strerror),
            hle_export!(_time64),
            hle_export!(_difftime64),
            hle_export!(_localtime64_s),
            hle_export!(_gmtime64_s),
            hle_export!(_gmtime64),
            hle_export!(_mktime64),
            hle_export!(_mkgmtime64),
            hle_export!(_ftime64),
            hle_export!(strftime),
            hle_export!(__acrt_iob_func),
            hle_export!(__p__commode),
            hle_export!(_set_fmode),
            hle_export!(fopen),
            hle_export!(_wfopen),
            hle_export!(fclose),
            hle_export!(fread),
            hle_export!(fwrite),
            hle_export!(fseek),
            hle_export!(_fseeki64),
            hle_export!(ftell),
            hle_export!(_ftelli64),
            hle_export!(fflush),
            hle_export!(fgetc),
            hle_export!(fputc),
            hle_export!(ferror),
            hle_export!(rewind),
            hle_export!(ungetc),
            hle_export!(setvbuf),
            hle_export!(_lock_file),
            hle_export!(_unlock_file),
            hle_export!(_wstat64),
            hle_export!(remove),
            hle_export!(__stdio_common_vsprintf),
            hle_export!(__stdio_common_vsprintf_s),
            hle_export!(__stdio_common_vsnprintf_s),
            hle_export!(__stdio_common_vfprintf),
            hle_export!(__stdio_common_vswprintf),
            hle_export!(__stdio_common_vswprintf_s),
            hle_export!(__stdio_common_vsnwprintf_s),
            hle_export!(__stdio_common_vsscanf),
            hle_export!(__stdio_common_vswscanf),
            hle_export!(QueryPerformanceCounter),
            hle_export!(QueryPerformanceFrequency),
            hle_export!(GetSystemTimeAsFileTime),
            hle_export!(GetCurrentProcess),
            hle_export!(GetCurrentProcessId),
            hle_export!(GetCurrentThreadId),
            hle_export!(IsDebuggerPresent),
            hle_export!(IsProcessorFeaturePresent),
            hle_export!(InitializeSListHead),
            hle_export!(GetLastError),
            hle_export!(SetLastError),
            hle_export!(GetLogicalProcessorInformation),
            hle_export!(GetLogicalProcessorInformationEx),
            hle_export!(GetSystemInfo),
            hle_export!(GetNativeSystemInfo),
            hle_export!(AcquireSRWLockExclusive),
            hle_export!(ReleaseSRWLockExclusive),
            hle_export!(AcquireSRWLockShared),
            hle_export!(ReleaseSRWLockShared),
            hle_export!(SleepConditionVariableSRW),
            hle_export!(SleepConditionVariableCS),
            hle_export!(WakeAllConditionVariable),
            hle_export!(WakeConditionVariable),
            hle_export!(InitializeConditionVariable),
            hle_export!(LocaleNameToLCID),
            hle_export!(AddVectoredExceptionHandler),
            hle_export!(RemoveVectoredExceptionHandler),
            hle_export!(RaiseException),
            hle_export!(InitializeCriticalSection),
            hle_export!(DeleteCriticalSection),
            hle_export!(EnterCriticalSection),
            hle_export!(LeaveCriticalSection),
            hle_export!(CreateEventW),
            hle_export!(SetEvent),
            hle_export!(ResetEvent),
            hle_export!(CloseHandle),
            hle_export!(WaitForSingleObject),
            hle_export!(GetStartupInfoW),
            hle_export!(MultiByteToWideChar),
            hle_export!(WideCharToMultiByte),
            hle_export!(LocalFree),
            hle_export!(BCryptOpenAlgorithmProvider),
            hle_export!(BCryptCloseAlgorithmProvider),
            hle_export!(BCryptGenRandom),
            hle_export!(UnhandledExceptionFilter),
            hle_export!(SetUnhandledExceptionFilter),
            hle_export!(RtlCaptureContext),
            hle_export!(RtlLookupFunctionEntry),
            hle_export!(RtlVirtualUnwind),
            hle_export!(__C_specific_handler),
            hle_export!(_CxxThrowException),
            hle_export!(__CxxFrameHandler4),
            hle_export!(__CxxFrameHandler3),
            hle_export!(__std_terminate),
            hle_export!(__std_exception_copy),
            hle_export!(__std_exception_destroy),
            hle_export!(__current_exception),
            hle_export!(__current_exception_context),
            hle_export!(__std_type_info_destroy_list),
            hle_export!(__std_type_info_compare),
            hle_export!(__RTDynamicCast),
            hle_export!(_purecall),
            hle_export!(_set_purecall_handler),
            hle_export!(GetCommandLineA),
            hle_export!(GetCommandLineW),
            hle_export!(GetCurrentThreadStackLimits),
            hle_export!(Sleep),
            hle_export!(GetTickCount64),
            hle_export!(GlobalMemoryStatusEx),
            hle_export!(VirtualAlloc),
            hle_export!(VirtualFree),
            hle_export!(InitializeCriticalSectionAndSpinCount),
            hle_export!(CreateMutexA),
            hle_export!(ReleaseMutex),
            hle_export!(CreateEventA),
            hle_export!(CreateSemaphoreW),
            hle_export!(CreateSemaphoreExW),
            hle_export!(ReleaseSemaphore),
            hle_export!(WaitForMultipleObjects),
            hle_export!(WaitForSingleObjectEx),
            hle_export!(FormatMessageA),
            hle_export!(GetSystemTimePreciseAsFileTime),
            hle_export!(FileTimeToSystemTime),
            hle_export!(SystemTimeToFileTime),
            hle_export!(RegisterClassExA),
            hle_export!(CreateWindowExA),
            hle_export!(ShowWindow),
            hle_export!(DefWindowProcA),
            hle_export!(PeekMessageA),
            hle_export!(TranslateMessage),
            hle_export!(DispatchMessageA),
            hle_export!(CreateThread),
            hle_export!(GetCurrentThread),
            hle_export!(ResumeThread),
            hle_export!(SuspendThread),
            hle_export!(SetThreadPriority),
            hle_export!(GetThreadPriority),
            hle_export!(SetThreadDescription),
            hle_export!(SetThreadGroupAffinity),
            hle_export!(SetThreadAffinityMask),
            hle_export!(TerminateThread),
            hle_export!(RegisterAppStateChangeNotification),
            hle_export!(RegisterAppConstrainedChangeNotification),
            hle_export!(UnregisterAppStateChangeNotification),
            hle_export!(UnregisterAppConstrainedChangeNotification),
            hle_export!(WSAStartup),
            hle_export!(WSACleanup),
            hle_export!(WSAGetLastError),
            hle_export!(WSAIoctl),
            HleExport { name: "#1", address: ws2_accept as usize },
            HleExport { name: "#2", address: ws2_bind as usize },
            HleExport { name: "#3", address: ws2_closesocket as usize },
            HleExport { name: "#4", address: ws2_connect as usize },
            HleExport { name: "#6", address: ws2_gethostbyname as usize },
            HleExport { name: "#7", address: ws2_getprotobyname as usize },
            HleExport { name: "#9", address: ws2_getservbyname as usize },
            HleExport { name: "#10", address: ws2_getservbyport as usize },
            HleExport { name: "#11", address: ws2_inet_addr as usize },
            HleExport { name: "#13", address: ws2_listen as usize },
            HleExport { name: "#16", address: ws2_recv as usize },
            HleExport { name: "#17", address: ws2_recvfrom as usize },
            HleExport { name: "#18", address: ws2_select as usize },
            HleExport { name: "#19", address: ws2_send as usize },
            HleExport { name: "#20", address: ws2_sendto as usize },
            HleExport { name: "#21", address: ws2_setsockopt as usize },
            HleExport { name: "#22", address: ws2_shutdown as usize },
            HleExport { name: "#23", address: ws2_socket as usize },
            HleExport { name: "#52", address: ws2_getpeername as usize },
            HleExport { name: "#57", address: ws2_getsockname as usize },
            HleExport { name: "#111", address: WSAGetLastError as usize },
            HleExport { name: "#115", address: WSAStartup as usize },
            HleExport { name: "#116", address: WSACleanup as usize },
            HleExport { name: "#151", address: WSAIoctl as usize },
            HleExport { name: "getaddrinfo", address: ws2_getaddrinfo as usize },
            HleExport { name: "freeaddrinfo", address: ws2_freeaddrinfo as usize },
            hle_export!(CoInitializeEx),
            hle_export!(CoUninitialize),
            hle_export!(CoCreateGuid),
            hle_export!(CoTaskMemFree),
            hle_export!(CoCreateInstance),
            hle_export!(PropVariantClear),
            hle_export!(StringFromGUID2),
            hle_export!(MoveFileExW),
            hle_export!(lstrcmpW),
            hle_export!(SetNamedPipeHandleState),
            hle_export!(WaitNamedPipeW),
            hle_export!(GetDateFormatEx),
            hle_export!(GetTimeFormatEx),
            hle_export!(GetThreadGroupAffinity),
            hle_export!(OpenThread),
            hle_export!(GetLocalTime),
            hle_export!(GetSystemTime),
            hle_export!(SetProcessPriorityBoost),
            hle_export!(GetUserDefaultGeoName),
            hle_export!(SetThreadIdealProcessorEx),
            hle_export!(DStorageGetFactory),
            HleExport {
                name: "?_Random_device@std@@YAIXZ",
                address: _Random_device as *const () as usize,
            },
            HleExport {
                name: "??0?$basic_iostream@_WU?$char_traits@_W@std@@@std@@QEAA@PEAV?$basic_streambuf@_WU?$char_traits@_W@std@@@1@@Z",
                address: basic_iostream_ctor as *const () as usize,
            },
            HleExport {
                name: "??0?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@IEAA@XZ",
                address: basic_streambuf_ctor as *const () as usize,
            },
            HleExport {
                name: "??0?$basic_iostream@DU?$char_traits@D@std@@@std@@QEAA@PEAV?$basic_streambuf@DU?$char_traits@D@std@@@1@@Z",
                address: basic_iostream_ctor as *const () as usize,
            },
            HleExport {
                name: "??0?$basic_streambuf@DU?$char_traits@D@std@@@std@@IEAA@XZ",
                address: basic_streambuf_ctor as *const () as usize,
            },
            HleExport {
                name: "??0?$basic_ios@DU?$char_traits@D@std@@@std@@IEAA@XZ",
                address: basic_ios_ctor as *const () as usize,
            },
            HleExport {
                name: "??0ios_base@std@@IEAA@XZ",
                address: ios_base_ctor as *const () as usize,
            },
            HleExport {
                name: "??1?$basic_ios@DU?$char_traits@D@std@@@std@@UEAA@XZ",
                address: stream_dtor_noop as *const () as usize,
            },
            HleExport {
                name: "??1?$basic_ios@_WU?$char_traits@_W@std@@@std@@UEAA@XZ",
                address: stream_dtor_noop as *const () as usize,
            },
            HleExport {
                name: "??1?$basic_iostream@DU?$char_traits@D@std@@@std@@UEAA@XZ",
                address: stream_dtor_noop as *const () as usize,
            },
            HleExport {
                name: "??1?$basic_iostream@_WU?$char_traits@_W@std@@@std@@UEAA@XZ",
                address: stream_dtor_noop as *const () as usize,
            },
            HleExport {
                name: "??1?$basic_streambuf@DU?$char_traits@D@std@@@std@@UEAA@XZ",
                address: stream_dtor_noop as *const () as usize,
            },
            HleExport {
                name: "??1?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@UEAA@XZ",
                address: stream_dtor_noop as *const () as usize,
            },
            HleExport {
                name: "??1ios_base@std@@UEAA@XZ",
                address: stream_dtor_noop as *const () as usize,
            },
            HleExport {
                name: "?_Lock@?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@UEAAXXZ",
                address: streambuf_lock as *const () as usize,
            },
            HleExport {
                name: "?_Unlock@?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@UEAAXXZ",
                address: streambuf_unlock as *const () as usize,
            },
            HleExport {
                name: "?_Lock@?$basic_streambuf@DU?$char_traits@D@std@@@std@@UEAAXXZ",
                address: streambuf_lock as *const () as usize,
            },
            HleExport {
                name: "?_Unlock@?$basic_streambuf@DU?$char_traits@D@std@@@std@@UEAAXXZ",
                address: streambuf_unlock as *const () as usize,
            },
            HleExport {
                name: "?flush@?$basic_ostream@_WU?$char_traits@_W@std@@@std@@QEAAAEAV12@XZ",
                address: ostream_flush as *const () as usize,
            },
            HleExport {
                name: "?flush@?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAAEAV12@XZ",
                address: ostream_flush as *const () as usize,
            },
            HleExport {
                name: "?widen@?$ctype@_W@std@@QEBA_WD@Z",
                address: ctype_widen as *const () as usize,
            },
            HleExport {
                name: "?sputc@?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@QEAAG_W@Z",
                address: sputc_w as *const () as usize,
            },
            HleExport {
                name: "?sputc@?$basic_streambuf@DU?$char_traits@D@std@@@std@@QEAAHD@Z",
                address: sputc_d as *const () as usize,
            },
            HleExport {
                name: "?getloc@ios_base@std@@QEBA?AVlocale@2@XZ",
                address: ios_base_getloc as *const () as usize,
            },
            HleExport {
                name: "?getloc@?$basic_streambuf@DU?$char_traits@D@std@@@std@@QEBA?AVlocale@2@XZ",
                address: ios_base_getloc as *const () as usize,
            },
            HleExport {
                name: "?classic@locale@std@@SAAEBV12@XZ",
                address: locale_classic as *const () as usize,
            },
            HleExport {
                name: "?_Getgloballocale@locale@std@@CAPEAV_Locimp@12@XZ",
                address: locale_getgloballocale as *const () as usize,
            },
            HleExport {
                name: "?_Init@locale@std@@CAPEAV_Locimp@12@_N@Z",
                address: locale_init as *const () as usize,
            },
            HleExport {
                name: "??0_Lockit@std@@QEAA@H@Z",
                address: lockit_ctor as *const () as usize,
            },
            HleExport {
                name: "??1_Lockit@std@@QEAA@XZ",
                address: lockit_dtor as *const () as usize,
            },
            HleExport {
                name: "_Mtx_init_in_situ",
                address: _Mtx_init_in_situ as *const () as usize,
            },
            HleExport {
                name: "_Mtx_destroy_in_situ",
                address: _Mtx_destroy_in_situ as *const () as usize,
            },
            HleExport {
                name: "_Mtx_lock",
                address: _Mtx_lock as *const () as usize,
            },
            HleExport {
                name: "_Mtx_unlock",
                address: _Mtx_unlock as *const () as usize,
            },
            HleExport {
                name: "_Query_perf_counter",
                address: _Query_perf_counter as *const () as usize,
            },
            HleExport {
                name: "_Query_perf_frequency",
                address: _Query_perf_frequency as *const () as usize,
            },
            HleExport {
                name: "_Xtime_get_ticks",
                address: _Xtime_get_ticks as *const () as usize,
            },
            HleExport {
                name: "?_Getcat@?$ctype@_W@std@@SA_KPEAPEBVfacet@locale@2@PEBV42@@Z",
                address: facet_getcat as *const () as usize,
            },
            HleExport {
                name: "?_Getcat@?$codecvt@DDU_Mbstatet@@@std@@SA_KPEAPEBVfacet@locale@2@PEBV42@@Z",
                address: facet_getcat as *const () as usize,
            },
            HleExport {
                name: "?_Makeloc@_Locimp@locale@std@@CAPEAV123@AEBV_Locinfo@3@HPEAV123@PEBV23@@Z",
                address: locimp_makeloc as *const () as usize,
            },
            HleExport {
                name: "?_New_Locimp@_Locimp@locale@std@@CAPEAV123@_N@Z",
                address: locimp_new as *const () as usize,
            },
            HleExport {
                name: "??Bid@locale@std@@QEAA_KXZ",
                address: locale_id_cast as *const () as usize,
            },
            HleExport {
                name: "?_Id_cnt@id@locale@std@@0HA",
                address: std::ptr::addr_of!(ID_CNT) as usize,
            },
            HleExport {
                name: "?id@?$ctype@_W@std@@2V0locale@2@A",
                address: std::ptr::addr_of!(CTYPE_W_ID) as usize,
            },
            HleExport {
                name: "?id@?$codecvt@DDU_Mbstatet@@@std@@2V0locale@2@A",
                address: std::ptr::addr_of!(CODECVT_ID) as usize,
            },
            HleExport {
                name: "?_Osfx@?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAXXZ",
                address: ostream_osfx as *const () as usize,
            },
            HleExport {
                name: "?_Osfx@?$basic_ostream@_WU?$char_traits@_W@std@@@std@@QEAAXXZ",
                address: ostream_osfx as *const () as usize,
            },
            HleExport {
                name: "?_Ipfx@?$basic_istream@DU?$char_traits@D@std@@@std@@QEAA_N_N@Z",
                address: istream_ipfx as *const () as usize,
            },
            HleExport {
                name: "?_Pninc@?$basic_streambuf@DU?$char_traits@D@std@@@std@@IEAAPEADXZ",
                address: streambuf_pninc as *const () as usize,
            },
            HleExport {
                name: "?_Pninc@?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@IEAAPEA_WXZ",
                address: streambuf_pninc as *const () as usize,
            },
            HleExport {
                name: "?_Gninc@?$basic_streambuf@DU?$char_traits@D@std@@@std@@IEAAPEADXZ",
                address: streambuf_gninc as *const () as usize,
            },
            HleExport {
                name: "?_Ios_base_dtor@ios_base@std@@CAXPEAV12@@Z",
                address: ios_base_dtor_static as *const () as usize,
            },
            HleExport {
                name: "??0_Locinfo@std@@QEAA@HPEBD@Z",
                address: locinfo_ctor as *const () as usize,
            },
            HleExport {
                name: "??1_Locinfo@std@@QEAA@XZ",
                address: locinfo_dtor as *const () as usize,
            },
            HleExport {
                name: "??4?$_Yarn@D@std@@QEAAAEAV01@PEBD@Z",
                address: yarn_assign as *const () as usize,
            },
            HleExport {
                name: "?setstate@?$basic_ios@_WU?$char_traits@_W@std@@@std@@QEAAXH_N@Z",
                address: basic_ios_setstate as *const () as usize,
            },
            HleExport {
                name: "?setstate@?$basic_ios@DU?$char_traits@D@std@@@std@@QEAAXH_N@Z",
                address: basic_ios_setstate as *const () as usize,
            },
            HleExport {
                name: "?clear@?$basic_ios@DU?$char_traits@D@std@@@std@@QEAAXH_N@Z",
                address: basic_ios_clear as *const () as usize,
            },
            HleExport {
                name: "?good@ios_base@std@@QEBA_NXZ",
                address: ios_base_good as *const () as usize,
            },
            HleExport {
                name: "?fail@ios_base@std@@QEBA_NXZ",
                address: ios_base_fail as *const () as usize,
            },
            HleExport {
                name: "?init@?$basic_ios@DU?$char_traits@D@std@@@std@@IEAAXPEAV?$basic_streambuf@DU?$char_traits@D@std@@@2@_N@Z",
                address: basic_ios_init as *const () as usize,
            },
            HleExport {
                name: "?xsputn@?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@MEAA_JPEB_W_J@Z",
                address: basic_streambuf_xsputn as *const () as usize,
            },
            HleExport {
                name: "?xsputn@?$basic_streambuf@DU?$char_traits@D@std@@@std@@MEAA_JPEBD_J@Z",
                address: basic_streambuf_xsputn as *const () as usize,
            },
            HleExport {
                name: "?xsgetn@?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@MEAA_JPEA_W_J@Z",
                address: basic_streambuf_xsgetn as *const () as usize,
            },
            HleExport {
                name: "?xsgetn@?$basic_streambuf@DU?$char_traits@D@std@@@std@@MEAA_JPEAD_J@Z",
                address: basic_streambuf_xsgetn as *const () as usize,
            },
            HleExport {
                name: "?sync@?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@MEAAHXZ",
                address: basic_streambuf_sync as *const () as usize,
            },
            HleExport {
                name: "?sync@?$basic_streambuf@DU?$char_traits@D@std@@@std@@MEAAHXZ",
                address: basic_streambuf_sync as *const () as usize,
            },
            HleExport {
                name: "?showmanyc@?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@MEAA_JXZ",
                address: basic_streambuf_showmanyc as *const () as usize,
            },
            HleExport {
                name: "?showmanyc@?$basic_streambuf@DU?$char_traits@D@std@@@std@@MEAA_JXZ",
                address: basic_streambuf_showmanyc as *const () as usize,
            },
            HleExport {
                name: "?uflow@?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@MEAAGXZ",
                address: basic_streambuf_uflow as *const () as usize,
            },
            HleExport {
                name: "?uflow@?$basic_streambuf@DU?$char_traits@D@std@@@std@@MEAAHXZ",
                address: basic_streambuf_uflow as *const () as usize,
            },
            HleExport {
                name: "?sbumpc@?$basic_streambuf@DU?$char_traits@D@std@@@std@@QEAAHXZ",
                address: basic_streambuf_sbumpc as *const () as usize,
            },
            HleExport {
                name: "?setbuf@?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@MEAAPEAV12@PEA_W_J@Z",
                address: basic_streambuf_setbuf as *const () as usize,
            },
            HleExport {
                name: "?setbuf@?$basic_streambuf@DU?$char_traits@D@std@@@std@@MEAAPEAV12@PEAD_J@Z",
                address: basic_streambuf_setbuf as *const () as usize,
            },
            HleExport {
                name: "?write@?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAAEAV12@PEBD_J@Z",
                address: basic_ostream_write as *const () as usize,
            },
            HleExport {
                name: "?read@?$basic_istream@DU?$char_traits@D@std@@@std@@QEAAAEAV12@PEAD_J@Z",
                address: basic_istream_read as *const () as usize,
            },
            HleExport {
                name: "?seekg@?$basic_istream@DU?$char_traits@D@std@@@std@@QEAAAEAV12@_JH@Z",
                address: basic_istream_seekg as *const () as usize,
            },
            HleExport {
                name: "?uncaught_exception@std@@YA_NXZ",
                address: std_uncaught_exception as *const () as usize,
            },
            HleExport {
                name: "?_Xlength_error@std@@YAXPEBD@Z",
                address: _Xlength_error as *const () as usize,
            },
            HleExport {
                name: "?_Xbad_function_call@std@@YAXXZ",
                address: _Xbad_function_call as *const () as usize,
            },
        ],
    }
}
