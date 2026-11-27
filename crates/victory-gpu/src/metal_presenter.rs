//! Native Metal presentation layer and CAMetalLayer presenter for Americas on macOS.

use std::sync::OnceLock;
use metal::*;
use objc::{class, msg_send, sel, sel_impl};
use objc::runtime::{Object, YES, NO};
use crate::metal_backend::context;
use crate::resource::ResourceDesc;

pub struct MetalPresenter {
    pub layer: MetalLayer,
    pub width: u32,
    pub height: u32,
    pub pipeline: RenderPipelineState,
    pub scene_texture: Texture,
}

unsafe impl Send for MetalPresenter {}
unsafe impl Sync for MetalPresenter {}

static PRESENTER: OnceLock<MetalPresenter> = OnceLock::new();

pub fn get_presenter() -> Option<&'static MetalPresenter> {
    PRESENTER.get()
}

const BLIT_SHADER: &str = r#"
#include <metal_stdlib>
using namespace metal;

struct VertexOut {
    float4 position [[position]];
    float2 uv;
};

vertex VertexOut vs_main(uint vid [[vertex_id]]) {
    VertexOut out;
    out.uv = float2((vid << 1) & 2, vid & 2);
    out.position = float4(out.uv * float2(2.0, -2.0) + float2(-1.0, 1.0), 0.0, 1.0);
    return out;
}

fragment float4 ps_compose(
    VertexOut in [[stage_in]],
    texture2d<float> scene [[texture(0)]],
    texture2d<float> overlay [[texture(1)]],
    sampler smp [[sampler(0)]]
) {
    float4 s = scene.sample(smp, in.uv);
    float4 o = overlay.sample(smp, in.uv);
    return float4(saturate(o.rgb + s.rgb * (1.0 - saturate(o.a))), 1.0);
}
"#;

impl MetalPresenter {
    pub fn new(layer: MetalLayer, width: u32, height: u32) -> Result<Self, String> {
        let ctx = context();
        layer.set_device(&ctx.device);
        layer.set_pixel_format(MTLPixelFormat::BGRA8Unorm);
        layer.set_drawable_size(core_graphics_types::geometry::CGSize::new(width as f64, height as f64));

        let compile_options = CompileOptions::new();
        let library = ctx.device
            .new_library_with_source(BLIT_SHADER, &compile_options)
            .map_err(|e| format!("Failed to compile blit shader: {e}"))?;

        let vs = library.get_function("vs_main", None).map_err(|e| format!("vs_main not found: {e}"))?;
        let ps = library.get_function("ps_compose", None).map_err(|e| format!("ps_compose not found: {e}"))?;

        let pipeline_desc = RenderPipelineDescriptor::new();
        pipeline_desc.set_vertex_function(Some(&vs));
        pipeline_desc.set_fragment_function(Some(&ps));
        pipeline_desc.color_attachments().object_at(0).unwrap().set_pixel_format(MTLPixelFormat::BGRA8Unorm);

        let pipeline = ctx.device
            .new_render_pipeline_state(&pipeline_desc)
            .map_err(|e| format!("Failed to create render pipeline: {e}"))?;

        let tex_desc = TextureDescriptor::new();
        tex_desc.set_pixel_format(MTLPixelFormat::BGRA8Unorm);
        tex_desc.set_width(width as u64);
        tex_desc.set_height(height as u64);
        tex_desc.set_usage(MTLTextureUsage::ShaderRead | MTLTextureUsage::RenderTarget);
        tex_desc.set_storage_mode(MTLStorageMode::Shared);
        let scene_texture = ctx.device.new_texture(&tex_desc);

        // Pre-fill initial frame with dark slate/blue so window is immediately visually active
        let mut initial_pixels = vec![0u8; (width * height * 4) as usize];
        for pixel in initial_pixels.chunks_exact_mut(4) {
            pixel[0] = 32;  // B
            pixel[1] = 24;  // G
            pixel[2] = 20;  // R
            pixel[3] = 255; // A
        }
        let region = MTLRegion {
            origin: MTLOrigin { x: 0, y: 0, z: 0 },
            size: MTLSize { width: width as u64, height: height as u64, depth: 1 },
        };
        scene_texture.replace_region(region, 0, initial_pixels.as_ptr().cast(), (width * 4) as u64);

        Ok(MetalPresenter {
            layer,
            width,
            height,
            pipeline,
            scene_texture,
        })
    }

    /// Presents a frame given optional framebuffer memory and description.
    pub fn present_frame(
        &self,
        buffer_ptr: Option<*const u8>,
        desc: Option<ResourceDesc>,
    ) -> Result<(), String> {
        if let (Some(data), Some(desc)) = (buffer_ptr, desc) {
            if !data.is_null() && desc.width > 0 && desc.height > 0 {
                let w = (desc.width as u32).min(self.width);
                let h = desc.height.min(self.height);
                let region = MTLRegion {
                    origin: MTLOrigin { x: 0, y: 0, z: 0 },
                    size: MTLSize { width: w as u64, height: h as u64, depth: 1 },
                };
                let bytes_per_row = (desc.width as u64) * 4;
                self.scene_texture.replace_region(
                    region,
                    0,
                    data.cast(),
                    bytes_per_row,
                );
            }
        }

        let drawable = self.layer.next_drawable().ok_or("Failed to get next Metal drawable")?;
        let ctx = context();
        let cmd = ctx.queue.new_command_buffer();

        let pass_desc = RenderPassDescriptor::new();
        let color_attachment = pass_desc.color_attachments().object_at(0).unwrap();
        color_attachment.set_texture(Some(drawable.texture()));
        color_attachment.set_load_action(MTLLoadAction::Clear);
        color_attachment.set_store_action(MTLStoreAction::Store);
        color_attachment.set_clear_color(MTLClearColor::new(0.0, 0.0, 0.0, 1.0));

        let encoder = cmd.new_render_command_encoder(&pass_desc);
        encoder.set_render_pipeline_state(&self.pipeline);
        encoder.set_fragment_texture(0, Some(&self.scene_texture));
        encoder.set_fragment_texture(1, Some(&self.scene_texture));

        let sampler_desc = SamplerDescriptor::new();
        sampler_desc.set_min_filter(MTLSamplerMinMagFilter::Linear);
        sampler_desc.set_mag_filter(MTLSamplerMinMagFilter::Linear);
        let sampler = ctx.device.new_sampler(&sampler_desc);
        encoder.set_fragment_sampler_state(0, Some(&sampler));

        encoder.draw_primitives(MTLPrimitiveType::Triangle, 0, 3);
        encoder.end_encoding();

        cmd.present_drawable(drawable);
        cmd.commit();
        Ok(())
    }

    /// Renders base 3D scene and UI overlay planes directly to CAMetalLayer drawable.
    pub fn present_planes(
        &self,
        scene: &TextureRef,
        overlay: Option<&TextureRef>,
    ) -> Result<(), String> {
        let drawable = self.layer.next_drawable().ok_or("Failed to get next Metal drawable")?;
        let ctx = context();
        let cmd = ctx.queue.new_command_buffer();

        let pass_desc = RenderPassDescriptor::new();
        let color_attachment = pass_desc.color_attachments().object_at(0).unwrap();
        color_attachment.set_texture(Some(drawable.texture()));
        color_attachment.set_load_action(MTLLoadAction::Clear);
        color_attachment.set_store_action(MTLStoreAction::Store);
        color_attachment.set_clear_color(MTLClearColor::new(0.0, 0.0, 0.0, 1.0));

        let encoder = cmd.new_render_command_encoder(&pass_desc);
        encoder.set_render_pipeline_state(&self.pipeline);
        encoder.set_fragment_texture(0, Some(scene));
        if let Some(over) = overlay {
            encoder.set_fragment_texture(1, Some(over));
        } else {
            encoder.set_fragment_texture(1, Some(scene));
        }

        let sampler_desc = SamplerDescriptor::new();
        sampler_desc.set_min_filter(MTLSamplerMinMagFilter::Linear);
        sampler_desc.set_mag_filter(MTLSamplerMinMagFilter::Linear);
        let sampler = ctx.device.new_sampler(&sampler_desc);
        encoder.set_fragment_sampler_state(0, Some(&sampler));

        encoder.draw_primitives(MTLPrimitiveType::Triangle, 0, 3);
        encoder.end_encoding();

        cmd.present_drawable(drawable);
        cmd.commit();
        Ok(())
    }
}

#[link(name = "AppKit", kind = "framework")]
unsafe extern "C" {
    fn NSApplicationLoad() -> u8;
}

#[repr(C)]
#[derive(Copy, Clone)]
struct CGPoint {
    x: f64,
    y: f64,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct CGSize {
    width: f64,
    height: f64,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct CGRect {
    origin: CGPoint,
    size: CGSize,
}

/// Creates a native macOS Cocoa window with an attached CAMetalLayer and initializes MetalPresenter.
pub fn create_native_window(title: &str, width: u32, height: u32) -> Result<(), String> {
    if PRESENTER.get().is_some() {
        return Ok(());
    }
    unsafe {
        NSApplicationLoad();
        let app: *mut Object = msg_send![class!(NSApplication), sharedApplication];
        let () = msg_send![app, setActivationPolicy: 0isize]; // NSApplicationActivationPolicyRegular

        let rect = CGRect {
            origin: CGPoint { x: 100.0, y: 100.0 },
            size: CGSize { width: width as f64, height: height as f64 },
        };

        let window: *mut Object = msg_send![class!(NSWindow), alloc];
        let style_mask: usize = 1 | 2 | 4 | 8; // Titled | Closable | Miniaturizable | Resizable
        let backing_store_buffered: usize = 2;
        let () = msg_send![
            window,
            initWithContentRect: rect
            styleMask: style_mask
            backing: backing_store_buffered
            defer: NO
        ];

        let title_cls = class!(NSString);
        let title_bytes = title.as_bytes();
        let title_ns: *mut Object = msg_send![
            title_cls,
            stringWithBytes: title_bytes.as_ptr()
            length: title_bytes.len()
            encoding: 4usize // NSUTF8StringEncoding
        ];
        let () = msg_send![window, setTitle: title_ns];

        let view: *mut Object = msg_send![window, contentView];
        let () = msg_send![view, setWantsLayer: YES];

        let layer = MetalLayer::new();
        let () = msg_send![view, setLayer: layer.as_ref()];

        let _: *mut Object = msg_send![window, retain];
        let () = msg_send![window, center];
        let () = msg_send![window, makeKeyAndOrderFront: std::ptr::null_mut::<Object>()];
        let () = msg_send![window, orderFrontRegardless];
        let () = msg_send![app, finishLaunching];
        let () = msg_send![app, activateIgnoringOtherApps: YES];

        let presenter = MetalPresenter::new(layer.clone(), width, height)?;
        let _ = PRESENTER.set(presenter);

        let raw_layer = layer.as_ref() as *const _ as *mut std::ffi::c_void;
        let bridge_ok = crate::d3dmetal_bridge_init(raw_layer, width, height);
        if bridge_ok {
            tracing::info!("D3DMetal bridge connected to CAMetalLayer window ({width}x{height})");
        } else {
            tracing::warn!("Failed to initialize D3DMetal bridge on CAMetalLayer");
        }

        let pool: *mut Object = msg_send![class!(NSAutoreleasePool), alloc];
        let pool: *mut Object = msg_send![pool, init];
        let () = msg_send![app, updateWindows];
        let () = msg_send![pool, drain];

        Ok(())
    }
}

/// Pumps macOS AppKit Cocoa events on the main thread until the worker thread finishes.
pub fn pump_cocoa_events_until(
    main: std::thread::JoinHandle<anyhow::Result<u32>>,
) -> anyhow::Result<u32> {
    unsafe {
        let app: *mut Object = msg_send![class!(NSApplication), sharedApplication];
        let title_cls = class!(NSString);
        let run_loop_bytes = b"kCFRunLoopDefaultMode\0";
        let run_loop_mode: *mut Object = msg_send![
            title_cls,
            stringWithUTF8String: run_loop_bytes.as_ptr()
        ];
        let date_class = class!(NSDate);
        while !main.is_finished() {
            let pool: *mut Object = msg_send![class!(NSAutoreleasePool), alloc];
            let pool: *mut Object = msg_send![pool, init];

            let until_date: *mut Object = msg_send![date_class, dateWithTimeIntervalSinceNow: 0.016f64];
            let event: *mut Object = msg_send![
                app,
                nextEventMatchingMask: usize::MAX
                untilDate: until_date
                inMode: run_loop_mode
                dequeue: YES
            ];
            if !event.is_null() {
                let event_type: usize = msg_send![event, type];
                if event_type == 10 { // NSKeyDown
                    let key_code: u16 = msg_send![event, keyCode];
                    let btn = match key_code {
                        36 | 49 => 0x4, // Return | Space -> A
                        51 => 0x8,      // Backspace -> B
                        7 => 0x10,      // X -> X
                        16 => 0x20,     // Y -> Y
                        53 => 0x1,      // Esc -> Menu
                        48 => 0x2,      // Tab -> View
                        _ => 0,
                    };
                    if btn != 0 {
                        unsafe extern "C" { fn metvl_press_macos_gamepad_button(button: u32); }
                        unsafe { metvl_press_macos_gamepad_button(btn) };
                    }
                } else if event_type == 11 { // NSKeyUp
                    let key_code: u16 = msg_send![event, keyCode];
                    let btn = match key_code {
                        36 | 49 => 0x4,
                        51 => 0x8,
                        7 => 0x10,
                        16 => 0x20,
                        53 => 0x1,
                        48 => 0x2,
                        _ => 0,
                    };
                    if btn != 0 {
                        unsafe extern "C" { fn metvl_release_macos_gamepad_button(button: u32); }
                        unsafe { metvl_release_macos_gamepad_button(btn) };
                    }
                }
                let () = msg_send![app, sendEvent: event];
                let () = msg_send![app, updateWindows];
            }
            let () = msg_send![pool, drain];
        }
        main.join().map_err(|_| anyhow::anyhow!("title main thread panicked"))?
    }
}
