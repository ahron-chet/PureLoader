# Anti-Hook PE Loader

## Overview

This project implements the **Anti-Hook PE Loader**, a custom solution for manually parsing a PE file and resolving all its DLLs in the Import Address Table (IAT) by directly parsing them from the Export Address Table (EAT) recursively (parsing also the dependencies of the dependencies to avoid any call to `LoadLibrary` and `GetProcAddress`). Unlike traditional reflective DLL loaders or PE loaders that use `LoadLibrary` and `GetProcAddress` to resolve IATs, which can be intercepted and hooked by EDRs solutions, this loader performs all operations manually to avoid EDR hooks.


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
```
PureLoader.exe --pe <PE path> [--debug]
```

The main function is a proof of concept (PoC) to run the entry point of a PE after parsing the EAT and IAT.

### As a Module

You can also use this project as a module in your code to run specific functions within a loaded PE file:

```cpp
RunDllFunction<void(*)()>("funcname", dllFile);
```
