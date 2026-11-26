//! Native Metal device, command queue, and unified memory manager for macOS Apple Silicon.

use std::sync::{Arc, OnceLock};
use metal::*;

pub struct MetalContext {
    pub device: Device,
    pub queue: CommandQueue,
}

static CONTEXT: OnceLock<Arc<MetalContext>> = OnceLock::new();

pub fn context() -> &'static Arc<MetalContext> {
    CONTEXT.get_or_init(|| {
        let device = Device::system_default().expect("Metal is not supported on this Mac");
        tracing::info!(name = device.name(), "Initialized native Metal context");
        let queue = device.new_command_queue();
        Arc::new(MetalContext { device, queue })
    })
}

/// A zero-copy buffer allocated directly in Apple Silicon Unified Memory.
/// Both CPU and GPU share the exact same physical address space.
pub struct UnifiedBuffer {
    pub buffer: Buffer,
    pub length: u64,
}

impl UnifiedBuffer {
    /// Creates a new buffer accessible to both CPU and GPU with zero copy.
    pub fn new(length: u64) -> Self {
        let ctx = context();
        let options = MTLResourceOptions::StorageModeShared | MTLResourceOptions::CPUCacheModeDefaultCache;
        let buffer = ctx.device.new_buffer(length, options);
        UnifiedBuffer { buffer, length }
    }

    /// Creates a buffer from existing host data, making it immediately visible to GPU.
    pub fn from_slice(data: &[u8]) -> Self {
        let ctx = context();
        let options = MTLResourceOptions::StorageModeShared;
        let buffer = ctx.device.new_buffer_with_data(
            data.as_ptr().cast(),
            data.len() as u64,
            options,
        );
        UnifiedBuffer {
            buffer,
            length: data.len() as u64,
        }
    }

    /// Direct pointer to memory for CPU reads and writes.
    #[inline]
    pub fn as_mut_ptr(&self) -> *mut u8 {
        self.buffer.contents().cast()
    }

    #[inline]
    pub fn as_ptr(&self) -> *const u8 {
        self.buffer.contents().cast()
    }

    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.as_ptr(), self.length as usize) }
    }

    #[inline]
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.as_mut_ptr(), self.length as usize) }
    }
}
