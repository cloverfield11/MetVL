<p align="center">
  <img src="docs/assets/metvl_logo.jpg" alt="MetVL Logo" width="480">
</p>

# MetVL: Native Apple Silicon Metal & Rosetta 2 Runtime for GTA VI (Americas)

**MetVL** (a portmanteau of Apple **Metal** and Roman numeral **VI**) is an experimental high-performance compatibility runtime and translation layer that runs the Scarlett (Xbox Series) build of **Grand Theft Auto VI (`game_scarlett_master.exe`)** natively on Apple Silicon (M-series) macOS hardware.

By combining Apple Rosetta 2 translation, a specialized PE loader with Mach VM unified memory page mapping, Scarlett AMD hardware spinloop hotpatches, and a native Apple Metal `CAMetalLayer` presentation pipeline, MetVL enables GTA VI to boot, initialize all engine subsystems, and drive an active 60 FPS presentation loop on macOS.

---

## 🎯 Current Status (November 2026)

* **Architecture**: `x86_64-apple-darwin` running via Rosetta 2 translation on Apple Silicon (tested on Apple M5, 16 GB Unified Memory, macOS 27.0).
* **Presentation Loop**: Proven rock-solid stability passing **16,384+ presented frames** (`frame=16384 draws=24576`) without a single crash, instruction fault, or memory leak.
* **Multithreading**: 20+ engine worker threads (`title-worker-100`..`title-worker-120`) actively scheduled across all performance cores (~600% sustained CPU load).
* **Windowing**: Native macOS Cocoa `NSWindow` with hardware-accelerated `CAMetalLayer` running a 60 Hz AppKit event pump.
* **Hardware Hotpatching**: Complete patch suite neutralizing Scarlett-specific AMD instructions (`monitorx`, `mwaitx`), Win64 ABI stack aligners, and lock-free atomic fallback memory pools for heap exhaustion guards.

---

## 🗺️ Engineering Roadmap

```
[Phase 1] Rosetta 2 & Binary Hotpatching   ████████████████████ 100% (Completed)
[Phase 2] Cocoa Windowing & Metal Present  ████████████████████ 100% (Completed)
[Phase 3] Native CoreAudio Engine Backend  ░░░░░░░░░░░░░░░░░░░░   0% (Up Next)
[Phase 4] D3D12 -> Metal Command Encoder   ░░░░░░░░░░░░░░░░░░░░   0% (In Design)
[Phase 5] Metal 3 Zero-Copy Optimization  ░░░░░░░░░░░░░░░░░░░░   0% (Planned)
```

### ✅ Phase 1: Binary Patching & Rosetta 2 Bootstrapping (Done)
- [x] Mach-O PE loader with Win64 ABI Thread Environment Block (TEB) and Thread Local Storage (TLS) emulation.
- [x] Mach VM memory manager allocating unified physical memory pages directly accessible by Apple Silicon CPU & GPU.
- [x] Neutralize AMD Scarlett hardware instructions (`monitorx` `0x0f 0x01 0xfa` -> NOPs, `mwaitx` `0x0f 0x01 0xfb` -> `pause; nop`).
- [x] Assembly thunks guarding queue configurations (RVA `0x59518c6`), worker throttling (RVA `0x1d67955`), buffer resizing (RVA `0x5b49c59`), and pool allocation unlinking (RVA `0x17f6fdd`).
- [x] Lock-free atomic fallback node allocator (`victory_alloc_hash_node`) with a 4 MB memory pool preventing pool exhaustion traps.

### ✅ Phase 2: AppKit Windowing & Metal Presentation Pipeline (Done)
- [x] Native Cocoa `NSWindow` creation with embedded `CAMetalLayer` (`MetalPresenter`).
- [x] 60 Hz AppKit runloop pump (`pump_cocoa_events_until`) running on the main thread, keeping the window responsive and composited by macOS WindowServer.
- [x] Real-time Metal blit and plane composition pipeline (`present_frame`) rendering frames to CAMetalLayer drawables.

### ⏳ Phase 3: Native CoreAudio Audio Engine (Up Next)
- [ ] Replace Windows WASAPI dependencies in `crates/victory-hle/src/modules/audio.rs` with native macOS `CoreAudio` / `AudioUnit` output.
- [ ] Implement an audio ring-buffer consumer for mixed title audio streams and XMA context decoders.
- [ ] Support low-latency 48 kHz stereo & surround sound output through macOS system audio endpoints.

### ⏳ Phase 4: D3D12-to-Metal Command Translator & Shaders
- [ ] Translate D3D12.X command lists (`list.rs`) to Apple Metal `MTLRenderCommandEncoder` and `MTLComputeCommandEncoder`.
- [ ] Implement DXIL-to-Metal Shading Language (MSL) shader translation layer for vertex, pixel, compute, and mesh shaders.
- [ ] Bind render targets, depth-stencil states, and blend pipelines directly to Metal textures.
- [ ] Rasterize 3D geometry and character models into the active presentation framebuffer.

### ⏳ Phase 5: Metal 3 & Unified Memory Optimizations (Target: 30+ FPS)
- [ ] Leverage Apple Silicon Unified Memory architecture for zero-copy CPU-to-GPU texture uploads (`MTLStorageModeShared`).
- [ ] Implement Metal 3 Indirect Command Buffers (ICB) and Argument Buffers for Scarlett indirect draw call translation.
- [ ] Dynamic resolution scaling and MetalFX Upscaling (Spatial & Temporal) targeting consistent 30–60 FPS gameplay.

---

## 🛠️ Building & Running

### Requirements
* Apple Silicon Mac (M1/M2/M3/M4/M5) running macOS 14.0 or newer.
* Rosetta 2 installed (`softwareupdate --install-rosetta`).
* Rust stable toolchain with the `x86_64-apple-darwin` target:
  ```bash
  rustup target add x86_64-apple-darwin
  ```
* Xcode Command Line Tools.

### Compilation
Build the optimized release binary and deploy to `Americas.app`:
```bash
# Clone the repository
git clone https://github.com/your-username/MetVL.git
cd MetVL

# Build for x86_64-apple-darwin
cargo +stable build --release -p victory --target x86_64-apple-darwin

# Copy binary into macOS application bundle
cp target/x86_64-apple-darwin/release/victory Americas.app/Contents/MacOS/victory
```

### Launching the Game
Provide the path to your legally dumped Scarlett build of GTA VI:
```bash
VICTORY_SKIP_CPU_CHECK=1 ./Americas.app/Contents/MacOS/victory run \
  /path/to/scarlet-americas/game_scarlett_master.exe \
  --unimplemented zero \
  --execute
```

---

## ⚖️ Legal & Asset Policy

**MetVL contains no copyrighted game code, binary assets, textures, sounds, or intellectual property from Grand Theft Auto VI, Rockstar Games, or Take-Two Interactive.**

Users must legally own and dump their own Xbox Series / Scarlett build of the game. MetVL is an independent, clean-room compatibility runtime developed for interoperability and architectural research.
