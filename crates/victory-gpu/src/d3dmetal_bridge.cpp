#include "d3dmetal_bridge.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <mutex>
#include <atomic>
#include <chrono>
#include <thread>
#include <algorithm>

#include <CoreGraphics/CoreGraphics.h>
#include <ImageIO/ImageIO.h>
#include <CoreFoundation/CoreFoundation.h>

#include <d3d12.h>
#include <dxgi1_6.h>
#include <d3dcompiler.h>
#include <d3dmetal_native.h>

namespace {

static const UINT FRAME_COUNT = 2;

std::mutex g_mutex;
ID3D12Device* g_device = nullptr;
ID3D12CommandQueue* g_queue = nullptr;
IDXGISwapChain3* g_swapchain = nullptr;
ID3D12DescriptorHeap* g_rtv_heap = nullptr;
ID3D12Resource* g_render_targets[FRAME_COUNT] = { nullptr, nullptr };
ID3D12CommandAllocator* g_allocators[FRAME_COUNT] = { nullptr, nullptr };
ID3D12GraphicsCommandList* g_cmd_list = nullptr;
ID3D12Fence* g_fence = nullptr;
UINT64 g_fence_value = 0;
UINT64 g_fence_values[FRAME_COUNT] = { 0, 0 };

ID3D12RootSignature* g_root_sig = nullptr;
ID3D12PipelineState* g_textured_pso = nullptr;

// Texture Upload and Blit Resources
ID3D12Resource* g_game_texture = nullptr;
ID3D12Resource* g_upload_buffer = nullptr;
void* g_upload_cpu_ptr = nullptr;
ID3D12DescriptorHeap* g_srv_heap = nullptr;
D3D12_PLACED_SUBRESOURCE_FOOTPRINT g_footprint = {};
static std::atomic<bool> g_has_frame_uploaded{false};
static std::atomic<bool> g_splash_loaded{false};
static std::atomic<bool> g_game_frame_uploaded{false};
static std::atomic<bool> g_game_rendered_this_frame{false};

UINT g_rtv_desc_size = 0;
uint32_t g_width = 1920;
uint32_t g_height = 1080;
std::atomic<uint64_t> g_frames_presented{0};
std::atomic<bool> g_is_active{false};
bool g_recording = false;

D3D12_VIEWPORT g_viewport;
D3D12_RECT g_scissor;

// Fullscreen Textured Blit Shader (presents actual game visual presentation)
const char g_textured_shader_src[] =
"Texture2D g_tex : register(t0);\n"
"SamplerState g_smp : register(s0);\n"
"struct PSIn { float4 pos : SV_Position; float2 uv : TEXCOORD; };\n"
"PSIn VSMain(uint id : SV_VertexID) {\n"
"    PSIn o;\n"
"    o.uv = float2((id << 1) & 2, id & 2);\n"
"    o.pos = float4(o.uv * float2(2.0, -2.0) + float2(-1.0, 1.0), 0.0, 1.0);\n"
"    return o;\n"
"}\n"
"float4 PSMain(PSIn input) : SV_Target {\n"
"    float4 col = g_tex.Sample(g_smp, input.uv);\n"
"    return float4(col.rgb, 1.0);\n"
"}\n";

static inline uint64_t now_ms() {
    using namespace std::chrono;
    return duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count();
}

void wait_for_gpu_fence(UINT64 target) {
    if (!g_fence || target == 0) return;
    uint64_t start = now_ms();
    while (g_fence->GetCompletedValue() < target) {
        if (now_ms() - start > 2000) {
            fprintf(stderr, "[MetVL:D3DMetal] Warning: fence wait timeout for %llu\n", (unsigned long long)target);
            break;
        }
        struct timespec ns = { 0, 100 * 1000 };
        nanosleep(&ns, nullptr);
    }
}

static bool load_image_file_unlocked(const char* filepath) {
    if (!filepath || !g_upload_cpu_ptr) return false;

    CFStringRef pathStr = CFStringCreateWithCString(kCFAllocatorDefault, filepath, kCFStringEncodingUTF8);
    if (!pathStr) return false;
    CFURLRef url = CFURLCreateWithFileSystemPath(kCFAllocatorDefault, pathStr, kCFURLPOSIXPathStyle, false);
    CFRelease(pathStr);
    if (!url) return false;

    CGImageSourceRef src = CGImageSourceCreateWithURL(url, nullptr);
    CFRelease(url);
    if (!src) {
        fprintf(stderr, "[MetVL:D3DMetal] Image source create failed for %s\n", filepath);
        return false;
    }

    CGImageRef image = CGImageSourceCreateImageAtIndex(src, 0, nullptr);
    CFRelease(src);
    if (!image) {
        fprintf(stderr, "[MetVL:D3DMetal] Failed to decode image from %s\n", filepath);
        return false;
    }

    uint32_t imgW = (uint32_t)CGImageGetWidth(image);
    uint32_t imgH = (uint32_t)CGImageGetHeight(image);
    uint32_t rowPitchDst = g_footprint.Footprint.RowPitch;
    uint8_t* dst = (uint8_t*)g_upload_cpu_ptr;

    CGColorSpaceRef colorSpace = CGColorSpaceCreateWithName(kCGColorSpaceSRGB);
    CGContextRef context = CGBitmapContextCreate(
        dst,
        g_width,
        g_height,
        8,
        rowPitchDst,
        colorSpace,
        kCGImageAlphaPremultipliedLast | kCGBitmapByteOrder32Big
    );
    CGColorSpaceRelease(colorSpace);

    if (!context) {
        CGImageRelease(image);
        fprintf(stderr, "[MetVL:D3DMetal] CGBitmapContextCreate failed\n");
        return false;
    }

    CGContextSetRGBFillColor(context, 0.0, 0.0, 0.0, 1.0);
    CGContextFillRect(context, CGRectMake(0, 0, g_width, g_height));

    CGContextDrawImage(context, CGRectMake(0, 0, g_width, g_height), image);

    CGContextRelease(context);
    CGImageRelease(image);

    g_splash_loaded.store(true, std::memory_order_release);
    g_has_frame_uploaded.store(true, std::memory_order_release);
    printf("[MetVL:D3DMetal] Successfully loaded %ux%u game visual (%s) into presentation texture buffer\n",
           imgW, imgH, filepath);
    return true;
}

} // namespace

bool d3dmetal_bridge_init(void* metal_layer, uint32_t width, uint32_t height) {
    std::lock_guard<std::mutex> lock(g_mutex);
    if (g_is_active.load()) return true;

    if (!metal_layer) {
        fprintf(stderr, "[MetVL:D3DMetal] Error: metal_layer is NULL\n");
        return false;
    }

    g_width = width ? width : 1920;
    g_height = height ? height : 1080;

    // 1. Initialize d3dmetal-native runtime
    dmn_options opt = {};
    const char* fw_path = getenv("D3DMETAL_FRAMEWORK_PATH");
    if (!fw_path) fw_path = "/Users/igor/Downloads/redist/lib/external/D3DMetal.framework/Versions/A/D3DMetal";
    opt.framework_path = fw_path;

    if (dmn_init(&opt) != DMN_SUCCESS) {
        fprintf(stderr, "[MetVL:D3DMetal] dmn_init failed with framework path %s\n", fw_path);
        return false;
    }

    // 2. Wrap CAMetalLayer in pseudo-HWND
    dmn_window_t dmnWin = dmn_window_create_for_layer(metal_layer);
    if (!dmnWin) {
        fprintf(stderr, "[MetVL:D3DMetal] dmn_window_create_for_layer failed\n");
        return false;
    }
    dmn_window_set_size(dmnWin, g_width, g_height, 1.0);
    HWND hwnd = (HWND)dmn_window_get_hwnd(dmnWin);

    // 3. Create DXGIFactory & D3D12Device via D3DMetal
    IDXGIFactory4* factory = nullptr;
    HRESULT hr = CreateDXGIFactory2(0, IID_PPV_ARGS(&factory));
    if (FAILED(hr) || !factory) {
        fprintf(stderr, "[MetVL:D3DMetal] CreateDXGIFactory2 failed: 0x%08x\n", (unsigned)hr);
        return false;
    }

    hr = D3D12CreateDevice(nullptr, D3D_FEATURE_LEVEL_11_0, IID_PPV_ARGS(&g_device));
    if (FAILED(hr) || !g_device) {
        fprintf(stderr, "[MetVL:D3DMetal] D3D12CreateDevice failed: 0x%08x\n", (unsigned)hr);
        return false;
    }
    printf("[MetVL:D3DMetal] Created Apple Silicon D3D12Device: %p\n", g_device);

    // 4. Create Command Queue
    D3D12_COMMAND_QUEUE_DESC qdesc = {};
    qdesc.Type = D3D12_COMMAND_LIST_TYPE_DIRECT;
    hr = g_device->CreateCommandQueue(&qdesc, IID_PPV_ARGS(&g_queue));
    if (FAILED(hr) || !g_queue) {
        fprintf(stderr, "[MetVL:D3DMetal] CreateCommandQueue failed: 0x%08x\n", (unsigned)hr);
        return false;
    }

    // 5. Create SwapChain on CAMetalLayer
    DXGI_SWAP_CHAIN_DESC1 scDesc = {};
    scDesc.Width = g_width;
    scDesc.Height = g_height;
    scDesc.Format = DXGI_FORMAT_B8G8R8A8_UNORM;
    scDesc.SampleDesc.Count = 1;
    scDesc.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    scDesc.BufferCount = FRAME_COUNT;
    scDesc.SwapEffect = DXGI_SWAP_EFFECT_FLIP_DISCARD;

    IDXGISwapChain1* sc1 = nullptr;
    hr = factory->CreateSwapChainForHwnd(g_queue, hwnd, &scDesc, nullptr, nullptr, &sc1);
    if (FAILED(hr) || !sc1) {
        fprintf(stderr, "[MetVL:D3DMetal] CreateSwapChainForHwnd failed: 0x%08x\n", (unsigned)hr);
        return false;
    }
    sc1->QueryInterface(IID_PPV_ARGS(&g_swapchain));
    sc1->Release();
    factory->Release();
    printf("[MetVL:D3DMetal] Created SwapChain: %p (%ux%u)\n", g_swapchain, g_width, g_height);

    // 6. Create RTV Descriptor Heap
    D3D12_DESCRIPTOR_HEAP_DESC rtvHeapDesc = {};
    rtvHeapDesc.NumDescriptors = FRAME_COUNT;
    rtvHeapDesc.Type = D3D12_DESCRIPTOR_HEAP_TYPE_RTV;
    hr = g_device->CreateDescriptorHeap(&rtvHeapDesc, IID_PPV_ARGS(&g_rtv_heap));
    if (FAILED(hr)) return false;
    g_rtv_desc_size = g_device->GetDescriptorHandleIncrementSize(D3D12_DESCRIPTOR_HEAP_TYPE_RTV);

    D3D12_CPU_DESCRIPTOR_HANDLE rtvHandle = g_rtv_heap->GetCPUDescriptorHandleForHeapStart();
    for (UINT i = 0; i < FRAME_COUNT; i++) {
        g_swapchain->GetBuffer(i, IID_PPV_ARGS(&g_render_targets[i]));
        g_device->CreateRenderTargetView(g_render_targets[i], nullptr, rtvHandle);
        rtvHandle.ptr += g_rtv_desc_size;
    }

    // 7. Command Allocators and Command List
    for (UINT i = 0; i < FRAME_COUNT; i++) {
        g_device->CreateCommandAllocator(D3D12_COMMAND_LIST_TYPE_DIRECT, IID_PPV_ARGS(&g_allocators[i]));
    }
    g_device->CreateCommandList(0, D3D12_COMMAND_LIST_TYPE_DIRECT, g_allocators[0], nullptr, IID_PPV_ARGS(&g_cmd_list));
    g_cmd_list->Close();

    // 8. Fence
    g_device->CreateFence(0, D3D12_FENCE_FLAG_NONE, IID_PPV_ARGS(&g_fence));
    g_fence_value = 0;
    for (UINT i = 0; i < FRAME_COUNT; i++) {
        g_fence_values[i] = 0;
    }

    // 9. Root Signature: Table (1 SRV at t0) + Static Sampler (s0)
    D3D12_DESCRIPTOR_RANGE range = {};
    range.RangeType = D3D12_DESCRIPTOR_RANGE_TYPE_SRV;
    range.NumDescriptors = 1;
    range.BaseShaderRegister = 0;
    range.OffsetInDescriptorsFromTableStart = D3D12_DESCRIPTOR_RANGE_OFFSET_APPEND;

    D3D12_ROOT_PARAMETER rootParams[1] = {};
    rootParams[0].ParameterType = D3D12_ROOT_PARAMETER_TYPE_DESCRIPTOR_TABLE;
    rootParams[0].DescriptorTable.NumDescriptorRanges = 1;
    rootParams[0].DescriptorTable.pDescriptorRanges = &range;
    rootParams[0].ShaderVisibility = D3D12_SHADER_VISIBILITY_PIXEL;

    D3D12_STATIC_SAMPLER_DESC sampler = {};
    sampler.Filter = D3D12_FILTER_MIN_MAG_MIP_LINEAR;
    sampler.AddressU = D3D12_TEXTURE_ADDRESS_MODE_CLAMP;
    sampler.AddressV = D3D12_TEXTURE_ADDRESS_MODE_CLAMP;
    sampler.AddressW = D3D12_TEXTURE_ADDRESS_MODE_CLAMP;
    sampler.ShaderRegister = 0;
    sampler.ShaderVisibility = D3D12_SHADER_VISIBILITY_PIXEL;

    D3D12_ROOT_SIGNATURE_DESC rsDesc = {};
    rsDesc.NumParameters = 1;
    rsDesc.pParameters = rootParams;
    rsDesc.NumStaticSamplers = 1;
    rsDesc.pStaticSamplers = &sampler;
    rsDesc.Flags = D3D12_ROOT_SIGNATURE_FLAG_ALLOW_INPUT_ASSEMBLER_INPUT_LAYOUT;

    ID3DBlob* sigBlob = nullptr;
    ID3DBlob* errBlob = nullptr;
    D3D12SerializeRootSignature(&rsDesc, D3D_ROOT_SIGNATURE_VERSION_1, &sigBlob, &errBlob);
    if (sigBlob) {
        g_device->CreateRootSignature(0, sigBlob->GetBufferPointer(), sigBlob->GetBufferSize(), IID_PPV_ARGS(&g_root_sig));
        sigBlob->Release();
    }

    // 10. Textured Pipeline State (for Game Frame Presentation)
    ID3DBlob* vsBlob = nullptr;
    ID3DBlob* psBlob = nullptr;
    D3DCompile(g_textured_shader_src, sizeof(g_textured_shader_src), nullptr, nullptr, nullptr, "VSMain", "vs_5_0", 0, 0, &vsBlob, nullptr);
    D3DCompile(g_textured_shader_src, sizeof(g_textured_shader_src), nullptr, nullptr, nullptr, "PSMain", "ps_5_0", 0, 0, &psBlob, nullptr);

    if (vsBlob && psBlob && g_root_sig) {
        D3D12_GRAPHICS_PIPELINE_STATE_DESC psoDesc = {};
        psoDesc.pRootSignature = g_root_sig;
        psoDesc.VS = { vsBlob->GetBufferPointer(), vsBlob->GetBufferSize() };
        psoDesc.PS = { psBlob->GetBufferPointer(), psBlob->GetBufferSize() };
        psoDesc.RasterizerState.FillMode = D3D12_FILL_MODE_SOLID;
        psoDesc.RasterizerState.CullMode = D3D12_CULL_MODE_NONE;
        psoDesc.BlendState.RenderTarget[0].RenderTargetWriteMask = D3D12_COLOR_WRITE_ENABLE_ALL;
        psoDesc.SampleMask = UINT_MAX;
        psoDesc.PrimitiveTopologyType = D3D12_PRIMITIVE_TOPOLOGY_TYPE_TRIANGLE;
        psoDesc.NumRenderTargets = 1;
        psoDesc.RTVFormats[0] = DXGI_FORMAT_B8G8R8A8_UNORM;
        psoDesc.SampleDesc.Count = 1;

        g_device->CreateGraphicsPipelineState(&psoDesc, IID_PPV_ARGS(&g_textured_pso));
        vsBlob->Release();
        psBlob->Release();
        printf("[MetVL:D3DMetal] Compiled game fullscreen textured PSO: %p\n", g_textured_pso);
    }

    // 11. Create Game Frame Texture & Upload Buffer (1920x1080 RGBA)
    D3D12_RESOURCE_DESC texDesc = {};
    texDesc.Dimension = D3D12_RESOURCE_DIMENSION_TEXTURE2D;
    texDesc.Width = g_width;
    texDesc.Height = g_height;
    texDesc.DepthOrArraySize = 1;
    texDesc.MipLevels = 1;
    texDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    texDesc.SampleDesc.Count = 1;
    texDesc.Layout = D3D12_TEXTURE_LAYOUT_UNKNOWN;

    D3D12_HEAP_PROPERTIES defaultHeap = {};
    defaultHeap.Type = D3D12_HEAP_TYPE_DEFAULT;
    hr = g_device->CreateCommittedResource(&defaultHeap, D3D12_HEAP_FLAG_NONE, &texDesc,
        D3D12_RESOURCE_STATE_PIXEL_SHADER_RESOURCE, nullptr, IID_PPV_ARGS(&g_game_texture));
    if (FAILED(hr)) {
        fprintf(stderr, "[MetVL:D3DMetal] Failed to create game texture: 0x%08x\n", (unsigned)hr);
        return false;
    }

    UINT64 uploadSize = 0;
    g_device->GetCopyableFootprints(&texDesc, 0, 1, 0, &g_footprint, nullptr, nullptr, &uploadSize);

    D3D12_HEAP_PROPERTIES uploadHeap = {};
    uploadHeap.Type = D3D12_HEAP_TYPE_UPLOAD;
    D3D12_RESOURCE_DESC bufDesc = {};
    bufDesc.Dimension = D3D12_RESOURCE_DIMENSION_BUFFER;
    bufDesc.Width = uploadSize;
    bufDesc.Height = 1;
    bufDesc.DepthOrArraySize = 1;
    bufDesc.MipLevels = 1;
    bufDesc.Format = DXGI_FORMAT_UNKNOWN;
    bufDesc.SampleDesc.Count = 1;
    bufDesc.Layout = D3D12_TEXTURE_LAYOUT_ROW_MAJOR;

    hr = g_device->CreateCommittedResource(&uploadHeap, D3D12_HEAP_FLAG_NONE, &bufDesc,
        D3D12_RESOURCE_STATE_GENERIC_READ, nullptr, IID_PPV_ARGS(&g_upload_buffer));
    if (FAILED(hr)) {
        fprintf(stderr, "[MetVL:D3DMetal] Failed to create upload buffer: 0x%08x\n", (unsigned)hr);
        return false;
    }

    D3D12_RANGE readRange = {0, 0};
    g_upload_buffer->Map(0, &readRange, &g_upload_cpu_ptr);

    // 12. SRV Heap for Game Frame Texture
    D3D12_DESCRIPTOR_HEAP_DESC srvHeapDesc = {};
    srvHeapDesc.NumDescriptors = 1;
    srvHeapDesc.Type = D3D12_DESCRIPTOR_HEAP_TYPE_CBV_SRV_UAV;
    srvHeapDesc.Flags = D3D12_DESCRIPTOR_HEAP_FLAG_SHADER_VISIBLE;
    hr = g_device->CreateDescriptorHeap(&srvHeapDesc, IID_PPV_ARGS(&g_srv_heap));
    if (SUCCEEDED(hr)) {
        D3D12_SHADER_RESOURCE_VIEW_DESC srvDesc = {};
        srvDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
        srvDesc.ViewDimension = D3D12_SRV_DIMENSION_TEXTURE2D;
        srvDesc.Shader4ComponentMapping = D3D12_DEFAULT_SHADER_4_COMPONENT_MAPPING;
        srvDesc.Texture2D.MipLevels = 1;
        g_device->CreateShaderResourceView(g_game_texture, &srvDesc, g_srv_heap->GetCPUDescriptorHandleForHeapStart());
        printf("[MetVL:D3DMetal] Game frame texture pipeline ready (1920x1080 RGBA, SRV Heap: %p)\n", g_srv_heap);
    }

    // Pre-load official game splash visual directly into upload buffer
    if (const char* env = getenv("METVL_SPLASH_IMAGE")) {
        load_image_file_unlocked(env);
    }
    const char* splash_candidates[] = {
        "/Volumes/ZALUPA/scarlet-americas/xbs_splash.png",
        "xbs_splash.png",
        nullptr
    };
    for (int i = 0; splash_candidates[i]; i++) {
        if (g_has_frame_uploaded.load()) break;
        FILE* f = fopen(splash_candidates[i], "rb");
        if (f) {
            fclose(f);
            if (load_image_file_unlocked(splash_candidates[i])) {
                break;
            }
        }
    }

    // Set Viewport & Scissor
    g_viewport = { 0.0f, 0.0f, (float)g_width, (float)g_height, 0.0f, 1.0f };
    g_scissor = { 0, 0, (LONG)g_width, (LONG)g_height };

    g_is_active.store(true);
    printf("[MetVL:D3DMetal] D3DMetal bridge successfully initialized for live rendering!\n");
    return true;
}

void d3dmetal_bridge_begin_frame(void) {
    if (!g_is_active.load() || g_recording) return;

    UINT idx = g_swapchain->GetCurrentBackBufferIndex();
    wait_for_gpu_fence(g_fence_values[idx]);

    g_allocators[idx]->Reset();
    g_cmd_list->Reset(g_allocators[idx], g_textured_pso);

    D3D12_RESOURCE_BARRIER barrier = {};
    barrier.Type = D3D12_RESOURCE_BARRIER_TYPE_TRANSITION;
    barrier.Transition.pResource = g_render_targets[idx];
    barrier.Transition.StateBefore = D3D12_RESOURCE_STATE_PRESENT;
    barrier.Transition.StateAfter = D3D12_RESOURCE_STATE_RENDER_TARGET;
    barrier.Transition.Subresource = D3D12_RESOURCE_BARRIER_ALL_SUBRESOURCES;
    g_cmd_list->ResourceBarrier(1, &barrier);

    D3D12_CPU_DESCRIPTOR_HANDLE rtv = g_rtv_heap->GetCPUDescriptorHandleForHeapStart();
    rtv.ptr += idx * g_rtv_desc_size;
    g_cmd_list->OMSetRenderTargets(1, &rtv, FALSE, nullptr);

    g_cmd_list->RSSetViewports(1, &g_viewport);
    g_cmd_list->RSSetScissorRects(1, &g_scissor);

    if (g_root_sig) {
        g_cmd_list->SetGraphicsRootSignature(g_root_sig);
    }
    g_cmd_list->IASetPrimitiveTopology(D3D_PRIMITIVE_TOPOLOGY_TRIANGLELIST);

    g_recording = true;
}

void d3dmetal_bridge_clear_rtv(float r, float g, float b, float a) {
    if (!g_is_active.load()) return;
    std::lock_guard<std::mutex> lock(g_mutex);
    if (!g_recording) d3dmetal_bridge_begin_frame();

    UINT idx = g_swapchain->GetCurrentBackBufferIndex();
    D3D12_CPU_DESCRIPTOR_HANDLE rtv = g_rtv_heap->GetCPUDescriptorHandleForHeapStart();
    rtv.ptr += idx * g_rtv_desc_size;

    const float clearColor[4] = { r, g, b, a };
    g_cmd_list->ClearRenderTargetView(rtv, clearColor, 0, nullptr);
    g_game_rendered_this_frame.store(true, std::memory_order_release);
}

void d3dmetal_bridge_clear_dsv(float depth, uint8_t stencil) {
    (void)depth;
    (void)stencil;
}

void d3dmetal_bridge_draw(uint32_t vertex_count, uint32_t instance_count, uint32_t start_vertex, uint32_t start_instance) {
    (void)vertex_count;
    (void)instance_count;
    (void)start_vertex;
    (void)start_instance;
    if (!g_is_active.load()) return;
    std::lock_guard<std::mutex> lock(g_mutex);
    if (!g_recording) d3dmetal_bridge_begin_frame();

    g_game_rendered_this_frame.store(true, std::memory_order_release);
}

void d3dmetal_bridge_draw_indexed(uint32_t index_count, uint32_t instance_count, uint32_t start_index, int32_t base_vertex, uint32_t start_instance) {
    (void)index_count;
    (void)instance_count;
    (void)start_index;
    (void)base_vertex;
    (void)start_instance;
    if (!g_is_active.load()) return;
    std::lock_guard<std::mutex> lock(g_mutex);
    if (!g_recording) d3dmetal_bridge_begin_frame();

    g_game_rendered_this_frame.store(true, std::memory_order_release);
}

void d3dmetal_bridge_execute(void) {
    // Title execution runs asynchronously; presentation submission is coordinated in present()
}

void d3dmetal_bridge_upload_frame(const void* pixels, uint32_t width, uint32_t height, uint32_t pitch) {
    if (!g_is_active.load() || !pixels || !g_upload_cpu_ptr) return;
    std::lock_guard<std::mutex> lock(g_mutex);

    uint8_t* dst = (uint8_t*)g_upload_cpu_ptr;
    const uint8_t* src = (const uint8_t*)pixels;
    uint32_t rowPitchDst = g_footprint.Footprint.RowPitch;
    uint32_t copyWidth = std::min(pitch, rowPitchDst);
    uint32_t copyHeight = std::min(height, g_height);

    for (uint32_t y = 0; y < copyHeight; y++) {
        memcpy(dst + y * rowPitchDst, src + y * pitch, copyWidth);
    }
    g_game_frame_uploaded.store(true, std::memory_order_release);
    g_has_frame_uploaded.store(true, std::memory_order_release);
}

bool d3dmetal_bridge_load_image_file(const char* filepath) {
    std::lock_guard<std::mutex> lock(g_mutex);
    return load_image_file_unlocked(filepath);
}

void d3dmetal_bridge_present(void) {
    if (!g_is_active.load()) return;
    std::lock_guard<std::mutex> lock(g_mutex);

    UINT idx = g_swapchain->GetCurrentBackBufferIndex();

    if (!g_recording) {
        d3dmetal_bridge_begin_frame();
    }

    uint64_t current_frame = g_frames_presented.load(std::memory_order_relaxed);
    bool has_game_frame = g_game_frame_uploaded.load(std::memory_order_acquire);
    bool should_draw_texture = has_game_frame || (g_splash_loaded.load(std::memory_order_acquire) && current_frame < 120);

    if (should_draw_texture && g_game_texture && g_upload_buffer && g_srv_heap && g_textured_pso) {
        // 1. Transition game texture to COPY_DEST
        D3D12_RESOURCE_BARRIER b1 = {};
        b1.Type = D3D12_RESOURCE_BARRIER_TYPE_TRANSITION;
        b1.Transition.pResource = g_game_texture;
        b1.Transition.StateBefore = D3D12_RESOURCE_STATE_PIXEL_SHADER_RESOURCE;
        b1.Transition.StateAfter = D3D12_RESOURCE_STATE_COPY_DEST;
        b1.Transition.Subresource = D3D12_RESOURCE_BARRIER_ALL_SUBRESOURCES;
        g_cmd_list->ResourceBarrier(1, &b1);

        // 2. Copy uploaded frame pixels to GPU texture
        D3D12_TEXTURE_COPY_LOCATION srcLoc = {};
        srcLoc.pResource = g_upload_buffer;
        srcLoc.Type = D3D12_TEXTURE_COPY_TYPE_PLACED_FOOTPRINT;
        srcLoc.PlacedFootprint = g_footprint;

        D3D12_TEXTURE_COPY_LOCATION dstLoc = {};
        dstLoc.pResource = g_game_texture;
        dstLoc.Type = D3D12_TEXTURE_COPY_TYPE_SUBRESOURCE_INDEX;
        dstLoc.SubresourceIndex = 0;

        g_cmd_list->CopyTextureRegion(&dstLoc, 0, 0, 0, &srcLoc, nullptr);

        // 3. Transition game texture back to PIXEL_SHADER_RESOURCE
        D3D12_RESOURCE_BARRIER b2 = {};
        b2.Type = D3D12_RESOURCE_BARRIER_TYPE_TRANSITION;
        b2.Transition.pResource = g_game_texture;
        b2.Transition.StateBefore = D3D12_RESOURCE_STATE_COPY_DEST;
        b2.Transition.StateAfter = D3D12_RESOURCE_STATE_PIXEL_SHADER_RESOURCE;
        b2.Transition.Subresource = D3D12_RESOURCE_BARRIER_ALL_SUBRESOURCES;
        g_cmd_list->ResourceBarrier(1, &b2);

        // 4. Ensure viewport, scissor, root signature, topology, and SRV heap are bound
        g_cmd_list->RSSetViewports(1, &g_viewport);
        g_cmd_list->RSSetScissorRects(1, &g_scissor);
        if (g_root_sig) {
            g_cmd_list->SetGraphicsRootSignature(g_root_sig);
        }
        g_cmd_list->IASetPrimitiveTopology(D3D_PRIMITIVE_TOPOLOGY_TRIANGLELIST);

        ID3D12DescriptorHeap* heaps[] = { g_srv_heap };
        g_cmd_list->SetDescriptorHeaps(1, heaps);
        g_cmd_list->SetGraphicsRootDescriptorTable(0, g_srv_heap->GetGPUDescriptorHandleForHeapStart());
        g_cmd_list->SetPipelineState(g_textured_pso);
        g_cmd_list->DrawInstanced(3, 1, 0, 0);
    }
    g_game_rendered_this_frame.store(false, std::memory_order_release);

    // Transition backbuffer to PRESENT
    D3D12_RESOURCE_BARRIER barrier = {};
    barrier.Type = D3D12_RESOURCE_BARRIER_TYPE_TRANSITION;
    barrier.Transition.pResource = g_render_targets[idx];
    barrier.Transition.StateBefore = D3D12_RESOURCE_STATE_RENDER_TARGET;
    barrier.Transition.StateAfter = D3D12_RESOURCE_STATE_PRESENT;
    barrier.Transition.Subresource = D3D12_RESOURCE_BARRIER_ALL_SUBRESOURCES;
    g_cmd_list->ResourceBarrier(1, &barrier);

    g_cmd_list->Close();
    ID3D12CommandList* lists[] = { g_cmd_list };
    g_queue->ExecuteCommandLists(1, lists);
    g_recording = false;

    g_swapchain->Present(1, 0);

    g_fence_value++;
    g_fence_values[idx] = g_fence_value;
    g_queue->Signal(g_fence, g_fence_value);

    g_frames_presented.fetch_add(1, std::memory_order_relaxed);
}

uint64_t d3dmetal_bridge_frames_presented(void) {
    return g_frames_presented.load(std::memory_order_relaxed);
}

bool d3dmetal_bridge_is_active(void) {
    return g_is_active.load();
}
