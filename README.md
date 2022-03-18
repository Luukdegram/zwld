# zwld

Experimental linker for wasm object files.
The idea is to implement a linker that stays close to wasm-ld in regards to features
~so that one day this could potentially be used within the Zig self-hosted compiler to incrementally
link Zig code with other wasm object files.~
With zwld now having been upstreamed, the main development of the linker is done directly within the Zig compiler. Features and improvements will be backported to zwld at one point. Until then, this repository is mostly inactive.

While there's no official specification for linking, `zwld` follows the wasm [tool-convention](https://github.com/WebAssembly/tool-conventions/blob/main/Linking.md) closely.
The initial goal is to support mvp features and have a base skeleton which would provide us with enough information on how
to integrate this within the Zig compiler. The first step is to make static linking work as specified by `tool-convention`,
once that is completed, dynamic linking will be tackled.

## Usage
```
Usage: zwld [options] [files...] -o [path]

Options:
-h, --help                         Print this help and exit
-o [path]                          Output path of the binary
--entry <entry>                    Name of entry point symbol
--global-base=<value>              Value from where the global data will start
--import-memory                    Import memory from the host environment
--import-table                     Import function table from the host environment
--initial-memory=<value>           Initial size of the linear memory
--max-memory=<value>               Maximum size of the linear memory
--merge-data-segments              Enable merging data segments
--no-entry                         Do not output any entry point
--stack-first                      Place stack at start of linear memory instead of after data
--stack-size=<value>               Specifies the stack size in bytes
```

## Building
`zwld` uses the latest Zig, which can either be [built from source](https://github.com/ziglang/zig/wiki/Building-Zig-From-Source) or you can download
the latest [binary](https://ziglang.org/download).
Zwld can then be built running the following command:
```
zig build [-Denable-logging]
```
Right now zwld only contains debug logging, which is hidden behind the `enable-logging` flag. It is set to `false` by default.
