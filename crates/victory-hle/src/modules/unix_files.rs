use std::path::{Path, PathBuf};
use std::sync::Mutex;
use crate::HleModule;

static DRIVES: Mutex<Vec<(char, PathBuf)>> = Mutex::new(Vec::new());

pub fn mount_at(letter: char, root: &Path) {
    let mut drives = DRIVES.lock().unwrap_or_else(|e| e.into_inner());
    drives.retain(|(l, _)| *l != letter);
    drives.push((letter, root.to_path_buf()));
}

pub(crate) fn module() -> HleModule {
    HleModule {
        name: "files",
        dlls: &["api-ms-win-core-file-*"],
        exports: vec![],
    }
}
