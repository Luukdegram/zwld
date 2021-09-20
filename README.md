# zwld

Experimental linker for wasm object files.
The idea is to implement a linker that stays close to wasm-ld in regards to features
so that one day this could potentially be used within the Zig self-hosted compiler to incrementally
link Zig code with other wasm object files.

While there's no official specification for linking, `zwld` follows the wasm [tool-convention](https://github.com/WebAssembly/tool-conventions/blob/main/Linking.md) closely.
The initial goal is to support mvp features and have a base skeleton which would provide us with enough information on how
to integrate this within the Zig compiler. The first step is to make static linking work as specified by `tool-convention`,
once that is completed, dynamic linking will be tackled.

## Usage
```sh
zwld [-h] [--help] <FILE>
           --help           Display this help and exit.
       -h, --h              Display summaries of the headers of each section.
       -o, --output <STR>   Path to file to write output to.
       -s, --symbols        Display the symbol table
```

An example from dumping all headers of an object file:
```sh
zwld test/trivial.obj.wasm -h

test/trivial.obj.wasm:      file format wasm 0x1

Sections:

    Type start=0x0000000e end=0x0000001f (size=0x00000011) count: 4
  Import start=0x00000025 end=0x00000082 (size=0x0000005d) count: 4
    Func start=0x00000088 end=0x0000008b (size=0x00000003) count: 2
    Code start=0x00000091 end=0x000000b5 (size=0x00000024) count: 2
    Data start=0x000000bb end=0x000000ce (size=0x00000013) count: 1
  Custom start=0x000000d4 end=0x00000135 (size=0x00000061) "linking"
  Custom start=0x0000013b end=0x00000155 (size=0x0000001a) "reloc.CODE"
```
