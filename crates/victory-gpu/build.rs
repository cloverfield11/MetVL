//! Fingerprints the shader translator, so that cached translations
//! (`src/shader_cache.rs`) last until the translator itself changes and not
//! only until the next build of anything.

use std::path::{Path, PathBuf};

fn files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).into_iter().flatten().flatten() {
        let path = entry.path();
        if path.is_dir() {
            files(&path, out);
        } else {
            out.push(path);
        }
    }
}

fn main() {
    let here = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap_or_default());
    let crates = here.join("..");
    let root = crates.join("..");
    // The translator, what it is built from, and the form entries are kept in.
    let mut all = vec![
        crates.join("victory-shader/Cargo.toml"),
        here.join("src/shader_cache.rs"),
        root.join("Cargo.lock"),
        root.join("rust-toolchain.toml"),
    ];
    let source = crates.join("victory-shader/src");
    println!("cargo:rerun-if-changed={}", source.display());
    files(&source, &mut all);
    all.sort();
    let mut hash = blake3::Hasher::new();
    for path in &all {
        println!("cargo:rerun-if-changed={}", path.display());
        // Names and line endings as they are in every checkout.
        let name = path.file_name().unwrap_or_default().to_string_lossy().into_owned();
        let bytes: Vec<u8> = std::fs::read(path).unwrap_or_default().into_iter().filter(|&b| b != 13).collect();
        hash.update(name.as_bytes());
        hash.update(&(bytes.len() as u64).to_le_bytes());
        hash.update(&bytes);
    }
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rustc-env=VICTORY_TRANSLATOR={}", hash.finalize().to_hex());

    #[cfg(target_os = "macos")]
    {
        println!("cargo:rerun-if-changed=src/d3dmetal_bridge.cpp");
        println!("cargo:rerun-if-changed=src/d3dmetal_bridge.h");

        let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());
        let obj_path = out_dir.join("d3dmetal_bridge.o");
        let lib_path = out_dir.join("libd3dmetal_bridge.a");

        let status = std::process::Command::new("clang++")
            .args(&[
                "-arch", "x86_64",
                "-std=c++17",
                "-c",
                "-I", "/Users/igor/Downloads/d3dmetal-native/include",
                "-I", "/Users/igor/Downloads/d3dmetal-native/include/native/directx",
                "-I", "/Users/igor/Downloads/d3dmetal-native/include/native/windows",
                "-I", "/Users/igor/Downloads/d3dmetal-native/subprojects/directx-native/include",
                "-DWIDL_EXPLICIT_AGGREGATE_RETURNS=1",
                "src/d3dmetal_bridge.cpp",
                "-o", obj_path.to_str().unwrap(),
            ])
            .status()
            .expect("failed to compile d3dmetal_bridge.cpp");
        assert!(status.success(), "clang++ compilation failed");

        let status = std::process::Command::new("ar")
            .args(&["crus", lib_path.to_str().unwrap(), obj_path.to_str().unwrap()])
            .status()
            .expect("failed to create libd3dmetal_bridge.a");
        assert!(status.success(), "ar failed");

        println!("cargo:rustc-link-search=native={}", out_dir.display());
        println!("cargo:rustc-link-lib=static=d3dmetal_bridge");
        println!("cargo:rustc-link-search=native=/Users/igor/Downloads/d3dmetal-native/build");
        println!("cargo:rustc-link-lib=dylib=d3dmetal-native");
        println!("cargo:rustc-link-lib=framework=QuartzCore");
        println!("cargo:rustc-link-lib=framework=Metal");
        println!("cargo:rustc-link-lib=framework=CoreGraphics");
        println!("cargo:rustc-link-lib=framework=ImageIO");
        println!("cargo:rustc-link-lib=framework=CoreFoundation");
        println!("cargo:rustc-link-lib=c++");
    }
}
