//! Implementations, one module per area of the console API.
//!
//! Adding an API: write an `extern "system"` function named exactly like
//! the import, then list it with `hle_export!` in the module's `module()`.
//! Run `victory census` over your titles to see what is still missing.
//!
//! Planned areas (driven by census results, not by completeness):
//! `file` (package paths), `thread` (TLS callbacks for title threads),
//! `xaudio2`, `xstore` stubs.

#[cfg(windows)]
pub mod apu;
pub mod audio;
pub mod d3d12x;
pub mod display;
pub mod dsp;
#[cfg(windows)]
pub mod dstorage;
#[cfg(windows)]
pub mod files;
#[cfg(not(windows))]
pub mod unix_crt;
#[cfg(not(windows))]
pub mod unix_files;
#[cfg(not(windows))]
pub use unix_files as files;
pub mod gameinput;
pub mod kernel;
#[cfg(windows)]
pub mod lifecycle;
#[cfg(not(windows))]
pub mod unix_lifecycle;
#[cfg(not(windows))]
pub use unix_lifecycle as lifecycle;
#[cfg(windows)]
pub mod media;
#[cfg(windows)]
pub mod net;
pub mod rpcrt4;
pub mod speech;
pub mod storage;
pub mod xasync;
pub mod xg;
pub mod xgame;
pub mod xgameruntime;
pub mod xgamesave;
pub mod xgameui;
#[cfg(windows)]
pub mod xmem;
#[cfg(not(windows))]
pub mod unix_xmem;
#[cfg(not(windows))]
pub use unix_xmem as xmem;
pub mod xnetworking;
pub mod xpackage;
pub mod xstore;
pub mod xsystem;
pub mod xuser;

use crate::HleModule;

pub(crate) fn all() -> Vec<HleModule> {
    let mut all = vec![
        kernel::module(),
        xgameruntime::module(),
        gameinput::module(),
        d3d12x::module(),
        audio::module(),
        dsp::module(),
        xg::module(),
    ];
    #[cfg(windows)]
    all.push(apu::module());
    #[cfg(windows)]
    all.push(media::module());
    #[cfg(windows)]
    all.push(dstorage::module());
    all.push(files::module());
    all.push(lifecycle::module());
    #[cfg(windows)]
    all.push(net::module());
    all.push(rpcrt4::module());
    all.push(xmem::module());
    #[cfg(not(windows))]
    all.push(unix_crt::module());
    all.push(xsystem::module());
    all
}
