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
       -r, --reloc          Display the the relocations
       -a, --all            Display section headers, symbols and relocations
```

An example from dumping all available information (using -a):
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

Symbol table:

 0: F binding=global visible=yes id=2 name=main
 1: D binding=local visible=yes id=0 name=.L.str
 2: F binding=global visible=yes id=0 name=__linear_memory
 3: F binding=local visible=yes id=3 name=.LSomeOtherFunction_bitcast
 4: F binding=global visible=yes id=1 name=__indirect_function_table

Relocations:

Relocations for section: 3 [4]
 R_WASM_MEMORY_ADDR_SLEB offset=0x000004 symbol=1
 R_WASM_FUNCTION_INDEX_LEB offset=0x00000a symbol=2
 R_WASM_FUNCTION_INDEX_LEB offset=0x000011 symbol=3
 R_WASM_FUNCTION_INDEX_LEB offset=0x00001e symbol=4
```
