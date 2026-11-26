//! Unix/macOS stubs and crash logging for platforms without native Windows debug APIs.

use std::path::PathBuf;

pub fn locate(address: usize) -> String {
    format!("{address:#x}")
}

pub fn log_crash(text: &str) {
    eprintln!("{text}");
}

pub fn log_crashes_to(_file: PathBuf) {}

pub fn note_title_output(_line: &str) {}

/// # Safety
/// No-op on Unix
pub unsafe fn report_unhandled(_info: *const std::ffi::c_void) {}

pub fn report_crashes() {}

pub fn disable_thread_calls(_base: usize) -> Option<bool> {
    Some(true)
}
