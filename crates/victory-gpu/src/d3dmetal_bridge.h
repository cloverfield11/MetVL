#ifndef D3DMETAL_BRIDGE_H
#define D3DMETAL_BRIDGE_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/// Initializes the D3DMetal bridge with a macOS CAMetalLayer.
bool d3dmetal_bridge_init(void* metal_layer, uint32_t width, uint32_t height);

/// Begins a new frame for recording commands.
void d3dmetal_bridge_begin_frame(void);

/// Clears the active render target view with RGBA color.
void d3dmetal_bridge_clear_rtv(float r, float g, float b, float a);

/// Clears depth/stencil view.
void d3dmetal_bridge_clear_dsv(float depth, uint8_t stencil);

/// Records a non-indexed draw command.
void d3dmetal_bridge_draw(uint32_t vertex_count, uint32_t instance_count, uint32_t start_vertex, uint32_t start_instance);

/// Records an indexed draw command.
void d3dmetal_bridge_draw_indexed(uint32_t index_count, uint32_t instance_count, uint32_t start_index, int32_t base_vertex, uint32_t start_instance);

/// Registers a pipeline state object compiled from DXIL shaders.
bool d3dmetal_bridge_register_pipeline(uint64_t pipeline_id, const void* vs_bytes, size_t vs_len, const void* ps_bytes, size_t ps_len);

/// Binds an active pipeline state for subsequent draw commands.
void d3dmetal_bridge_set_pipeline(uint64_t pipeline_id);

/// Submits recorded commands to the Apple Silicon GPU queue.
void d3dmetal_bridge_execute(void);

/// Presents the backbuffer to the live macOS Cocoa window.
void d3dmetal_bridge_present(void);

/// Blits external frame pixels (RGBA/BGRA) into the swapchain backbuffer.
void d3dmetal_bridge_upload_frame(const void* pixels, uint32_t width, uint32_t height, uint32_t pitch);

/// Returns the total number of frames presented through D3DMetal.
uint64_t d3dmetal_bridge_frames_presented(void);

/// Returns whether the bridge is initialized and ready.
bool d3dmetal_bridge_is_active(void);

/// Loads an image file (e.g. PNG) directly into the presentation texture buffer.
bool d3dmetal_bridge_load_image_file(const char* filepath);

#ifdef __cplusplus
}
#endif

#endif // D3DMETAL_BRIDGE_H
