//! Native Metal presentation layer and CAMetalLayer presenter for Americas on macOS.

use std::sync::Arc;
use metal::*;
use crate::metal_backend::{context, UnifiedBuffer};

pub struct MetalPresenter {
    pub layer: MetalLayer,
    pub width: u32,
    pub height: u32,
    pub pipeline: RenderPipelineState,
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

        Ok(MetalPresenter {
            layer,
            width,
            height,
            pipeline,
        })
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

use objc::{class, msg_send, sel, sel_impl};
use objc::runtime::{Object, YES, NO};

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
pub fn create_native_window(title: &str, width: u32, height: u32) -> Result<MetalPresenter, String> {
    unsafe {
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

        let () = msg_send![window, center];
        let () = msg_send![window, makeKeyAndOrderFront: std::ptr::null_mut::<Object>()];

        MetalPresenter::new(layer, width, height)
    }
}
