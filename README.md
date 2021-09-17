# zwld

Experimental linker for wasm object files.
The idea is to implement a linker that stays close to wasm-ld in regards to features
so that one day this could potentially be used within the Zig self-hosted compiler to incrementally
link Zig code with other wasm object files.

While there's no official specification for linking, `zwld` follows the wasm [tool-convention](https://github.com/WebAssembly/tool-conventions/blob/main/Linking.md) closely.
The initial goal is to support mvp features and have a base skeleton which would provide us with enough information on how
to integrate this within the Zig compiler. The first step is to make static linking work as specified by `tool-convention`,
once that is completed, dynamic linking will be tackled.
