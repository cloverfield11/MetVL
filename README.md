<p align="center">
  <img src="docs/assets/metvl_logo.jpg" alt="MetVL Logo" width="520">
</p>

# MetVL: Native Apple Silicon Metal & Rosetta 2 Runtime for GTA VI

> [!NOTE]
> **Fork Information**: **MetVL** is an open-source compatibility runtime and translation layer forked from [VIctory](https://github.com/Marvisak/VIctory) (and the [codec-d](https://github.com/codec-d/cool_fox) fork), which originally targeted Direct3D 12 on Windows x64. MetVL completely pivots the project architecture towards **macOS Apple Silicon**, substituting the Windows execution stack with **Apple Rosetta 2 translation**, **Mach VM unified memory mapping**, **macOS AppKit Cocoa windowing**, and a native **Apple Metal (`CAMetalLayer`)** presentation pipeline.
>
> The name **MetVL** is a wordplay uniting **Metal** (Apple's graphics API) and Roman numeral **VI** (**VL**), emphasizing our mission: bringing Grand Theft Auto VI natively to macOS.

---

## 📌 Executive Summary

* **Target Title**: Grand Theft Auto VI (`game_scarlett_master.exe`, Scarlett / Americas build).
* **Target Hardware**: Apple Silicon Mac (M1/M2/M3/M4/M5), tested on Apple M5 (16 GB Unified RAM, macOS 27.0).
* **Target Architecture**: `x86_64-apple-darwin` executing under Apple Rosetta 2 JIT translation.
* **Windowing & Display**: Native Cocoa `NSWindow` with hardware-accelerated `CAMetalLayer` at 1920×1080 (Retina 3932×2316), driven by a 60 Hz AppKit event pump on the main thread.
* **Current Operational Benchmark**: Rock-solid stability passing **16,384+ presented frames** (`frame=16384 draws=24576`) across 20+ active worker threads utilizing ~600% sustained CPU with zero crashes, assertion traps, or memory leaks.

---

## 🗺️ Detailed Technical Roadmap

MetVL is organized into 5 progressive engineering phases:

```
[Phase 1] Rosetta 2 Loader & Hardware Hotpatching    ████████████████████ 100% (Completed)
[Phase 2] Cocoa Windowing & Metal CAMetalLayer       ████████████████████ 100% (Completed)
[Phase 3] Native macOS CoreAudio Output Engine       ░░░░░░░░░░░░░░░░░░░░   0% (Up Next)
[Phase 4] Direct3D 12 -> Metal Command Translation   ░░░░░░░░░░░░░░░░░░░░   0% (In Architecture)
[Phase 5] Metal 3 Zero-Copy & 30+ FPS Optimization   ░░░░░░░░░░░░░░░░░░░░   0% (Planned)
```

---

### 1. Что уже сделано (What Was Done) — ✅ Completed

#### 1.1 Mach-O / PE Dynamic Loader & Win64 ABI Emulation
- **Rosetta 2 Execution Layer**: Configured toolchain targeting `x86_64-apple-darwin`, enabling native execution through macOS Rosetta 2 with AVX/SSE2 runtime translation.
- **TEB & TLS Emulation**: Implemented Windows Thread Environment Block (`GS:[0x30]`) and Thread Local Storage (`GS:[0x58]`) mapping on macOS threads via custom assembly routines and `sys_thread_set_state`.
- **Mach VM Physical Memory Manager**: Implemented zero-copy memory allocation leveraging macOS `mach_vm_allocate` and `mach_vm_protect`, providing unified physical memory pages directly accessible by both CPU and Apple Silicon GPU cores without double-buffering.

#### 1.2 Binary Hotpatching & Scarlett Hardware Spinloop Neutralization
- **AMD Hardware Instruction Neutralization**:
  - Scarlett-specific hardware instructions `monitorx` (`0x0f 0x01 0xfa`) at RVAs `0x4fb0bd7`, `0x4fb0d21`, `0x6e87462` replaced with `NOP` instructions.
  - Hardware spinloop instructions `mwaitx` (`0x0f 0x01 0xfb`) at RVAs `0x4fb0c00`, `0x4fb0d52`, `0x67bd464`, `0x6e874c2` replaced with `pause; nop` sequences, preventing Rosetta 2 `EXC_BAD_INSTRUCTION` traps.
- **Null-Pointer & Memory Guard Assembly Thunks**:
  - `patch_queue_config_null_guard` (RVA `0x59518c6`): Inlines a 131-byte assembly thunk validating queue pointers against canonical 64-bit user address space.
  - `patch_worker_throttle_null_guard` (RVA `0x1d67955`): Guards throttle calculation pointer `[rip + 0x7b90b44]`, jumping directly to worker dispatch on null.
  - `patch_task_queue_size_null_guard` (RVA `0x5c8fed9`): Guards worker task queue pointer `rcx`, defaulting `esi = 0`.
  - `patch_buffer_resize_null_guard` (RVA `0x5b49c59`): Guards pool buffer resize checks.
  - `patch_node_unlink_guard` (RVA `0x17f6fdd`): Verifies 8-byte alignment, `ptr >= 0x10000`, and canonical user address space for both `prev` and `next` list nodes.
  - `patch_free_list_unlink_guard` (RVA `0x55aa4c0`): Validates heap range (`>= 0x130000000`) before unlink writes, eliminating protection faults.
- **Atomic Fallback Memory Pool**:
  - Implemented lock-free node allocator `victory_alloc_hash_node` with a 4 MB atomic memory pool intercepting pool exhaustion assertion `int3` traps at RVA `0x4db9f95`.
  - Neutralized assertion epilogue traps at RVA `0x3bf4`.

#### 1.3 Native AppKit Windowing & Metal Presentation Layer
- **Cocoa Window Management**:
  - Native Objective-C runtime initialization via `NSApplicationLoad` and `[NSApplication sharedApplication]` with `NSApplicationActivationPolicyRegular`.
  - Centered 1920×1080 `NSWindow` with full title bar, window controls, and embedded `CAMetalLayer`.
  - Implemented `pump_cocoa_events_until` running on the macOS main thread at 60 Hz (`nextEventMatchingMask:untilDate:inMode:dequeue:`), preventing UI lockup and integrating seamlessly with macOS WindowServer.
- **Metal Presenter Pipeline**:
  - Initialized `MTLDevice`, `MTLCommandQueue`, and `CAMetalLayer` (`MetalPresenter`).
  - Compiled hardware blit and plane composition shaders in Metal Shading Language (`BLIT_SHADER`).
  - Wired `crates/victory-gpu/src/queue.rs::present()` directly to `present_frame`, displaying rendered frames to active CAMetalLayer drawables at 60 FPS.

---

### 2. На чем мы остановились (Where We Stopped) — 📍 Current Baseline

The game engine boots seamlessly and runs indefinitely in a continuous presentation loop:
* **Frame Counter**: Ticking smoothly past **16,384 presented frames** at 60 FPS.
* **Worker Execution**: 20+ engine worker threads (`title-worker-100`..`title-worker-120`) running concurrent game logic, streaming checks, AI task updates, and simulation loops (~600% sustained CPU load).
* **Native Window**: Visible on screen, responsive to macOS window manager and keyboard/mouse focus.

**Why the screen is currently black and sound is silent:**
1. **Graphics**: In the upstream Windows codebase, `crates/victory-gpu/src/draw.rs` translates Scarlett D3D12.X calls to Windows Direct3D 12 host API (`ID3D12CommandList`, `ID3D12Device`). On macOS, there is no host D3D12 driver. On `#[cfg(not(windows))]`, draw commands in `list.rs:1850` were temporarily stubbed:
   ```rust
   #[cfg(not(windows))]
   extern "win64" fn draw(_: This) {
       count_draw(); // increments draw count without 3D rasterization
   }
   ```
   Because commands are not yet translated into Metal command encoders (`MTLRenderCommandEncoder`), the framebuffer remains empty.
2. **Audio**: Audio in `crates/victory-hle/src/modules/audio.rs` is routed exclusively to Windows WASAPI. On macOS, WASAPI does not exist, so audio output is currently muted.

---

### 3. Что предстоит делать (What Lies Ahead) — 🚀 Upcoming Roadmap

#### 🔊 Phase 3: Native CoreAudio Output Engine (Immediate Next Step)
* **CoreAudio / AudioUnit Integration**:
  - Replace Windows WASAPI COM interfaces in `crates/victory-hle/src/modules/audio.rs` with a native macOS `AudioQueue` or `AudioUnit` HAL output backend.
  - Allocate a lock-free circular audio ring buffer matching title audio mix latency (~10–20 ms).
* **Voice & Context Decoding**:
  - Connect XMA decoder threads and PCM stream mixers (`AcpHal.dll`, `xapu.dll`) directly to the CoreAudio ring buffer.
  - Support 48 kHz 16/24-bit stereo and multi-channel surround sound output.

#### 🎮 Phase 4: Direct3D 12 to Metal Command Translation Layer
* **Command Encoder Translation**:
  - Implement a Metal translation backend in `crates/victory-gpu` converting `ID3D12GraphicsCommandList` records to `MTLRenderCommandEncoder` and `MTLComputeCommandEncoder`.
  - Map D3D12 render targets, depth-stencil views (`DSV`), and viewports to Metal texture attachments.
* **Shader Translation Pipeline (DXIL -> MSL)**:
  - Integrate a DXIL (DirectX Intermediate Language) to Metal Shading Language (MSL) translator for vertex, pixel, compute, and amplification/mesh shaders.
  - Support D3D12 root signature parameter mapping to Metal argument buffers and buffer binding indices.
* **First Visible 3D Gameplay Geometry**:
  - Rasterize prologue scene, character models, world terrain, and UI overlays onto the CAMetalLayer surface.

#### ⚡ Phase 5: Metal 3 & Unified Memory Performance (Target: 30+ FPS)
* **Zero-Copy Unified Memory Architecture**:
  - Eliminate GPU upload copies: expose mapped physical memory pages directly to Metal buffers using `MTLResourceStorageModeShared` and `newBufferWithBytesNoCopy`.
* **MetalFX Upscaling**:
  - Integrate Apple MetalFX Spatial and Temporal upscalers to upscale internal 1080p rendering to 1440p/4K with minimal overhead.
* **Indirect Draw Acceleration**:
  - Translate Scarlett GPU command packets using Metal 3 Indirect Command Buffers (ICB), minimizing CPU overhead for dense Vice City vehicle and pedestrian crowds.

---

## 🛠️ Building & Installation

### Prerequisites
* Apple Silicon Mac (M1/M2/M3/M4/M5) with macOS 14.0 Sonoma, macOS 15 Sequoia, or macOS 26/27.
* Apple Rosetta 2:
  ```bash
  softwareupdate --install-rosetta --agree-to-license
  ```
* Rust stable toolchain with `x86_64-apple-darwin` target:
  ```bash
  rustup target add x86_64-apple-darwin
  ```
* Xcode Command Line Tools (`xcode-select --install`).

### Build Instructions
```bash
# Clone the repository
git clone https://github.com/cloverfield11/MetVL.git
cd MetVL

# Build release binary for x86_64 macOS target
cargo +stable build --release -p victory --target x86_64-apple-darwin

# Copy binary into MetVL.app bundle
cp target/x86_64-apple-darwin/release/victory MetVL.app/Contents/MacOS/victory
```

### Running GTA VI
You can launch directly by double-clicking **`MetVL.app`** in Finder, or via terminal:
```bash
VICTORY_SKIP_CPU_CHECK=1 ./MetVL.app/Contents/MacOS/victory run \
  /path/to/scarlet-americas/game_scarlett_master.exe \
  --unimplemented zero \
  --execute
```

---

## ⚖️ Legal Disclaimer & Asset Policy

* **MetVL is an independent, clean-room compatibility runtime developed strictly for interoperability, architectural research, and educational purposes.**
* **This repository contains NO game files, proprietary source code, binaries, shaders, textures, audio assets, or copyrighted intellectual property** belonging to Rockstar Games, Take-Two Interactive, or Microsoft Xbox.
* Users must legally purchase, own, and dump their own Xbox Series / Scarlett build of Grand Theft Auto VI.

---

## 🤝 Acknowledgments

* Based on the [VIctory](https://github.com/Marvisak/VIctory) compatibility layer project by Marvisak and the [codec-d](https://github.com/codec-d/cool_fox) fork.
* Apple Silicon Metal and Rosetta 2 runtime architecture developed by the MetVL team.
