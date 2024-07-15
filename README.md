# PureLoader: An Anti-Hooking PE Loader 

## Overview

PureLoader is a PE Loader with an EDR anti-hooking capability. It does so by loading a PE, resolving its DLL dependencies through recursive parsing, calculating function pointers from the EAT, and updating the IAT of the loaded PE with unhooked functions. This allows running known and signed tools, such as Mimikatz, in-memory.

Unlike traditional reflective PE loaders that use `LoadLibrary` and `GetProcAddress` to resolve IATs, PureLoader avoids EDR hooks by using custom  implementations of `LoadLibrary` and `GetProcAddress`.


## Key Features

- **Manual PE Parsing**: Reads and parses PE headers to gather necessary information about sections, imports, and exports.
- **Recursive Dependency Resolution**: Resolves all dependencies recursively by parsing the IAT directly from the EAT, ensuring that all function addresses are correctly resolved without relying on potentially hooked APIs.
- **Export Address Table (EAT) Parsing**: Directly reads the EAT of each dependency to resolve function addresses. This ensures that all function pointers are accurately mapped to their original addresses, bypassing any hooks that EDR solutions might place on functions like `GetProcAddress`.
- **Export Registration**: Registers all exported functions of the loaded DLLs for accurate resolution of function addresses.
- **TLS Callback Execution**: Executes Thread Local Storage (TLS) callbacks as specified in the PE headers.
- **Base Relocation**: Applies base relocations to ensure the loaded PE file can be correctly executed at its allocated base address.
- **Full Implementation of LoadLibrary & GetProcAddress**: Provides a complete manual implementation of these functions to avoid using potentially hooked system calls.


## Usage

### As a Standalone Executable

1. **Compile the project** using your preferred C++ compiler.
2. **Run the executable** with the desired PE file as an argument. Use the `--debug` flag for detailed debugging output.
```powershell
PureLoader.exe --pe <PE path> [--debug]
```

The main function is a proof of concept (PoC) to run the entry point of a PE after parsing the EAT and IAT.

### As a Module

You can also use this project as a module in your code to run specific functions within a loaded PE file:

```cpp
RunDllFunction<void(*)()>("funcname", dllFile);
```
