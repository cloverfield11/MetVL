//! D3D12.X on host D3D12.
//!
//! D3D12.X records commands from code inlined into the title, which writes
//! packets into the command list while its put pointer is below a limit and
//! calls the list's method otherwise. Our lists keep the limits at zero, so
//! every command arrives here as a call, to be run on host D3D12. The
//! title's GPU addresses are CPU addresses (console memory is unified).
//!
//! [`device`] is the device object titles create, [`dxgi`] its adapter side,
//! [`resource`] heaps and resources, [`fence`] fences, [`queue`] command
//! queues, [`list`] command allocators and lists, [`descriptor`]
//! descriptor heaps, [`root`] root signatures, [`query`] query heaps,
//! [`signature`] command signatures, [`pipeline`] pipeline states,
//! [`frame`] frame pacing, [`object`] what all console graphics objects
//! share, [`console`] which console model the title sees. Planned:
//! `present` (swap chain).

#[cfg(windows)]
mod ambient;
#[cfg(all(windows, feature = "diagnostics"))]
mod capture;
#[cfg(windows)]
mod compose;
pub mod console;
#[cfg(all(windows, feature = "diagnostics"))]
mod copystat;
#[cfg(all(windows, feature = "diagnostics"))]
mod faultbook;
#[cfg(windows)]
mod cores;
pub mod descriptor;
pub mod device;
#[cfg(windows)]
mod draw;
pub mod dxgi;
pub mod fence;
pub mod frame;
#[cfg(all(windows, feature = "diagnostics"))]
mod book;
#[cfg(windows)]
mod host;
#[cfg(windows)]
mod indirect;
#[cfg(windows)]
mod inplace;
#[cfg(windows)]
mod land;
pub mod list;
pub mod object;
pub mod pipeline;
#[cfg(windows)]
mod picked;
#[cfg(windows)]
mod pool;
#[cfg(all(windows, feature = "diagnostics"))]
mod popwatch;
#[cfg(windows)]
mod primitive;
pub mod query;
pub mod queue;
#[cfg(all(windows, feature = "diagnostics"))]
pub mod replay;
#[cfg(windows)]
mod residency;
pub mod resource;
pub mod root;
#[cfg(windows)]
mod safecopy;
#[cfg(windows)]
mod sampler;
#[cfg(windows)]
pub mod shader_cache;
#[cfg(windows)]
mod memory;
#[cfg(windows)]
mod shadow;
#[cfg(windows)]
mod tiles;
pub mod signature;
mod switch;
#[cfg(all(windows, feature = "diagnostics"))]
mod ab;
#[cfg(windows)]
mod tdr;
#[cfg(windows)]
mod texture;
pub mod timeline;
#[cfg(windows)]
pub mod titlewrite;
#[cfg(windows)]
mod upload;
#[cfg(windows)]
mod watch;
#[cfg(windows)]
mod texback;

#[cfg(target_os = "macos")]
pub mod metal_backend;
#[cfg(target_os = "macos")]
pub mod metal_presenter;
#[cfg(target_os = "macos")]
pub use metal_presenter::{MetalPresenter, create_native_window, pump_cocoa_events_until};
#[cfg(target_os = "macos")]
pub use metal_backend::{context, UnifiedBuffer};

#[cfg(target_os = "macos")]
unsafe extern "C" {
    pub fn d3dmetal_bridge_init(metal_layer: *mut std::ffi::c_void, width: u32, height: u32) -> bool;
    pub fn d3dmetal_bridge_begin_frame();
    pub fn d3dmetal_bridge_clear_rtv(r: f32, g: f32, b: f32, a: f32);
    pub fn d3dmetal_bridge_clear_dsv(depth: f32, stencil: u8);
    pub fn d3dmetal_bridge_draw(vertex_count: u32, instance_count: u32, start_vertex: u32, start_instance: u32);
    pub fn d3dmetal_bridge_draw_indexed(index_count: u32, instance_count: u32, start_index: u32, base_vertex: i32, start_instance: u32);
    pub fn d3dmetal_bridge_register_pipeline(
        pipeline_id: u64,
        vs_bytes: *const u8,
        vs_len: usize,
        ps_bytes: *const u8,
        ps_len: usize,
    ) -> bool;
    pub fn d3dmetal_bridge_set_pipeline(pipeline_id: u64);
    pub fn d3dmetal_bridge_set_graphics_constants(slot: u32, count: u32, values: *const u32, offset: u32);
    pub fn d3dmetal_bridge_set_viewports(count: u32, vps: *const f32);
    pub fn d3dmetal_bridge_set_scissors(count: u32, rects: *const i32);
    pub fn d3dmetal_bridge_set_targets(count: u32, handles: *const u64, depth: u64);
    pub fn d3dmetal_bridge_execute();
    pub fn d3dmetal_bridge_present();
    pub fn d3dmetal_bridge_upload_frame(pixels: *const u8, width: u32, height: u32, pitch: u32);
    pub fn d3dmetal_bridge_load_image_file(filepath: *const std::ffi::c_char) -> bool;
    pub fn d3dmetal_bridge_frames_presented() -> u64;
    pub fn d3dmetal_bridge_is_active() -> bool;
}

#[cfg(windows)]
pub use host::on_failure;

/// Whether `switch` is on now, if it is one of those `VICTORY_AB` turns on and
/// off while the title runs (`ab`).
#[cfg(all(windows, feature = "diagnostics"))]
pub fn switched(switch: &str) -> Option<bool> {
    ab::pick(switch)
}

/// What the frame is at (`copystat::phase`), for the sampling profiler.
#[cfg(all(windows, feature = "diagnostics"))]
pub fn frame_phase() -> u32 {
    copystat::phase()
}
#[cfg(windows)]
pub use inplace::{title_memory_freeing, title_memory_section, title_memory_section_gone, title_memory_view};
#[cfg(windows)]
pub use watch::{
    kernel_writing, title_memory_allocated, title_memory_freed, title_memory_reading, title_memory_remapped,
    title_memory_remapping, title_memory_splitting, title_memory_unmapping, title_memory_written,
    writing as kernel_will_write,
};
#[cfg(not(windows))]
pub struct KernelWrite;
#[cfg(not(windows))]
pub fn kernel_writing(_at: usize, _len: usize) -> KernelWrite { KernelWrite }
#[cfg(not(windows))]
pub fn kernel_will_write(_at: usize, _len: usize) {}
#[cfg(not(windows))]
pub fn title_memory_written(_at: usize, _len: usize, _pages: bool) {}
