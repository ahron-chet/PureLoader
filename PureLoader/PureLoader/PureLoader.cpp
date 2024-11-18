#include <iostream>
#include <fstream>
#include <cstdlib>
#include <map>
#include <set>
#include <vector>
#include <sstream>
#include <algorithm>
#include <cstdio>
#include <memory>
#include <windows.h>

using runnDllMain = BOOL(WINAPI*)(HINSTANCE dll, DWORD reason, LPVOID reserved);

struct PE_BASE_INFO {
    std::string fullpath;
    PVOID baseAddress;
    PIMAGE_NT_HEADERS64 pNtHeaders;
    std::map<std::string, FARPROC> functions;
};

struct LoaderContext {
    std::map<std::string, std::unique_ptr<PE_BASE_INFO>> loadedDlls;
    std::set<std::string> readedDlls;
};

std::ostream* debugout = nullptr;

void DebugLog(const std::string& message) {
    if (debugout) {
        (*debugout) << message << std::endl;
    }
}

void stringToLower(std::string& str) {
    std::transform(str.begin(), str.end(), str.begin(), [](unsigned char c) { return std::tolower(c); });
}

PVOID readFile(const char* filename, size_t* fileSize) {
    std::ifstream file(filename, std::ios::binary | std::ios::ate);
    if (!file) {
        return nullptr;
    }

    *fileSize = file.tellg();
    void* buffer = std::malloc(*fileSize);
    if (!buffer) {
        return nullptr;
    }

    file.seekg(0, std::ios::beg);
    file.read((char*)buffer, *fileSize);
    file.close();
    return buffer;
}

PE_BASE_INFO* findDllInfoByPath(const std::string& path, LoaderContext* context) {
    for (const auto& pair : context->loadedDlls) {
        if (pair.second->fullpath == path) {
            return pair.second.get();
        }
    }
    return nullptr;
}

std::string GetFullPathForDll(const std::string& dllName) {
    HMODULE hModule = LoadLibraryA(dllName.c_str());
    if (!hModule) {
        std::cerr << "Failed to load DLL: " << dllName << "\n";
        return "";
    }

    char charPath[MAX_PATH];
    if (!GetModuleFileNameA(hModule, charPath, MAX_PATH)) {
        FreeLibrary(hModule);
        return "";
    }
    FreeLibrary(hModule);

    std::string path(charPath);
    stringToLower(path);
    return path;
}

PVOID GetFixedBaseAddress(PIMAGE_NT_HEADERS64 pNTHeaders) {
    DebugLog("Size Of image: " + std::to_string(pNTHeaders->OptionalHeader.SizeOfImage));
    return VirtualAlloc(0, pNTHeaders->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
}

void GetHeaders(PVOID pDllfile, PIMAGE_DOS_HEADER* pDOSHeader, PIMAGE_NT_HEADERS64* pNTHeaders) {
    *pDOSHeader = (PIMAGE_DOS_HEADER)pDllfile;
    *pNTHeaders = (PIMAGE_NT_HEADERS64)((LPBYTE)pDllfile + (*pDOSHeader)->e_lfanew);
}

void WriteHeaders(PVOID pDllfile, PVOID baseAddress, PIMAGE_NT_HEADERS64 pNTHeaders) {
    DebugLog("Size of headers: " + std::to_string(pNTHeaders->OptionalHeader.SizeOfHeaders));
    std::memcpy(baseAddress, pDllfile, pNTHeaders->OptionalHeader.SizeOfHeaders);
}

void WriteSections(PVOID baseAddress, PVOID pDllfile, PIMAGE_DOS_HEADER pDOSHeader, PIMAGE_NT_HEADERS64 pNTHeaders) {
    for (int i = 0; i < pNTHeaders->FileHeader.NumberOfSections; i++) {
        PIMAGE_SECTION_HEADER pSectionHeader =
            (PIMAGE_SECTION_HEADER)((LPBYTE)baseAddress + pDOSHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS64)
                + (i * sizeof(IMAGE_SECTION_HEADER)));

        DebugLog(std::string((char*)pSectionHeader->Name));
        DebugLog("Virtual Address: " + std::to_string(pSectionHeader->VirtualAddress));
        DebugLog("Raw offset: " + std::to_string(pSectionHeader->PointerToRawData));
        DebugLog("Size of raw data: " + std::to_string(pSectionHeader->SizeOfRawData));
        DebugLog("Virtual Size: " + std::to_string(pSectionHeader->Misc.VirtualSize));

        if (pSectionHeader->SizeOfRawData > 0) {
            DebugLog("Writing section to: " + std::to_string((uintptr_t)((PVOID)((LPBYTE)baseAddress + pSectionHeader->VirtualAddress))));
            std::memcpy((PVOID)((LPBYTE)baseAddress + pSectionHeader->VirtualAddress),
                (PVOID)((LPBYTE)pDllfile + pSectionHeader->PointerToRawData),
                pSectionHeader->SizeOfRawData);
        }
        DebugLog("");
    }
}

FARPROC getFunctionAddress(const std::string& dllNameStr, const std::string& funcNameStr, LoaderContext* context) {
    auto dllIt = context->loadedDlls.find(dllNameStr);
    if (dllIt != context->loadedDlls.end()) {
        PE_BASE_INFO* dllInfo = dllIt->second.get();
        auto funcIt = dllInfo->functions.find(funcNameStr);
        if (funcIt != dllInfo->functions.end()) {
            return funcIt->second;
        }
    }
    return nullptr;
}

bool FixImports(PIMAGE_NT_HEADERS64 pNTHeaders, PVOID baseAddress, bool rec, LoaderContext* context) {
    if (pNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size > 0) {
        PVOID importPtr = (PVOID)((LPBYTE)baseAddress + pNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
        IMAGE_IMPORT_DESCRIPTOR ImportDesc = *(IMAGE_IMPORT_DESCRIPTOR*)importPtr;
        while (ImportDesc.Name != 0) {
            char* dllName = (char*)((LPBYTE)baseAddress + ImportDesc.Name);
            std::string dllNameStr(dllName);

            PVOID pOft = (PVOID)((LPBYTE)baseAddress + ImportDesc.OriginalFirstThunk);
            PVOID pfirstthunk = (PVOID)((LPBYTE)baseAddress + ImportDesc.FirstThunk);
            IMAGE_THUNK_DATA64 thunk = *(IMAGE_THUNK_DATA64*)pOft;
            while (thunk.u1.Function < 0x8000000000000000 && thunk.u1.Function != 0) {
                LPBYTE pNameAddress = (LPBYTE)baseAddress + thunk.u1.AddressOfData;
                char* funcName = (char*)(pNameAddress + 2);
                std::string funcNamestr(funcName);
                DebugLog("  Function name: " + funcNamestr);

                FARPROC functionAddress;
                if (rec) {
                    functionAddress = GetProcAddress(LoadLibraryA(dllNameStr.c_str()), funcNamestr.c_str());
                }
                else {
                    functionAddress = getFunctionAddress(dllNameStr, funcNamestr, context);
                }

                if (functionAddress) {
                    DebugLog("      Function Address: " + std::to_string((uintptr_t)functionAddress));
                    *(FARPROC*)pfirstthunk = functionAddress;
                }
                else {
                    std::cerr << "Unable to locate function: " << funcNamestr << " in custom mapped functions\n";
                    exit(12);
                    return false;
                }
                pfirstthunk = (PVOID)((LPBYTE)pfirstthunk + sizeof(void*));
                pOft = (PVOID)((LPBYTE)pOft + sizeof(IMAGE_THUNK_DATA64));
                thunk = *(IMAGE_THUNK_DATA64*)pOft;
            }
            importPtr = (PVOID)((LPBYTE)importPtr + sizeof(IMAGE_IMPORT_DESCRIPTOR));
            ImportDesc = *(IMAGE_IMPORT_DESCRIPTOR*)importPtr;
        }
    }
    return true;
}

void ResolveDependencies(const std::string& dllName, PVOID pPefile, bool rec, LoaderContext* context) {
    DebugLog("Resolving dependencies for: " + dllName);

    if (context->loadedDlls.find(dllName) != context->loadedDlls.end()) {
        return;
    }

    const std::string dllPath = GetFullPathForDll(dllName);
    PE_BASE_INFO* foundDllInfo = findDllInfoByPath(dllPath, context);
    if (foundDllInfo != nullptr) {
        context->loadedDlls[dllName] = std::make_unique<PE_BASE_INFO>(*foundDllInfo);
        return;
    }

    PVOID pDllfile;
    if (pPefile == nullptr) {
        DebugLog("Reading data for :" + dllPath);
        size_t fileSize;
        pDllfile = readFile(dllPath.c_str(), &fileSize);
        DebugLog("Successfully read DLL: " + dllPath + ", Size: " + std::to_string(fileSize) + " bytes");
        if (!pDllfile) {
            std::cerr << "Failed to read the DLL: " << dllPath << "\n";
            return;
        }
    }
    else {
        pDllfile = pPefile;
    }

    PIMAGE_DOS_HEADER pDOSHeader;
    PIMAGE_NT_HEADERS64 pNTHeaders;
    GetHeaders(pDllfile, &pDOSHeader, &pNTHeaders);

    PVOID baseAddress = GetFixedBaseAddress(pNTHeaders);
    DebugLog("Allocated base address: " + std::to_string((uintptr_t)baseAddress) + " for DLL: " + dllPath);

    WriteHeaders(pDllfile, baseAddress, pNTHeaders);
    WriteSections(baseAddress, pDllfile, pDOSHeader, pNTHeaders);

    GetHeaders(baseAddress, &pDOSHeader, &pNTHeaders);

    if (!baseAddress) {
        std::cerr << "Unable to allocate base address for: " << dllPath << "\n";
        std::free(pDllfile);
        return;
    }

    auto dllInfo = std::make_unique<PE_BASE_INFO>();
    dllInfo->baseAddress = baseAddress;
    dllInfo->pNtHeaders = pNTHeaders;
    dllInfo->fullpath = dllPath;
    context->loadedDlls[dllName] = std::move(dllInfo);

    if (pNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size > 0) {
        PVOID importPtr = (PVOID)((LPBYTE)baseAddress + pNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
        IMAGE_IMPORT_DESCRIPTOR ImportDesc = *(IMAGE_IMPORT_DESCRIPTOR*)importPtr;

        while (ImportDesc.Name != 0) {
            char* importedDllName = (char*)((LPBYTE)baseAddress + ImportDesc.Name);
            std::string fullPath = GetFullPathForDll(importedDllName);

            if (fullPath.empty()) {
                std::cerr << "Skipping API set DLL: " << importedDllName << "\n";
                std::free(pDllfile);
                return;
            }
            else {
                DebugLog("Found imported DLL: " + std::string(importedDllName) + ", Full path: " + fullPath);
                if (rec) {
                    ResolveDependencies(importedDllName, nullptr, true, context);
                }
            }
            importPtr = (PVOID)((LPBYTE)importPtr + sizeof(IMAGE_IMPORT_DESCRIPTOR));
            ImportDesc = *(IMAGE_IMPORT_DESCRIPTOR*)importPtr;
        }
    }
    else {
        DebugLog("DLL " + dllPath + " has no imports.");
    }
    std::free(pDllfile);
    DebugLog("Freed memory for DLL: " + dllPath);
}

void BaseRelocation(PVOID baseAddress, PIMAGE_NT_HEADERS64 pNTHeaders) {
    LONG64 delta = (LONG64)baseAddress - (LONG64)pNTHeaders->OptionalHeader.ImageBase;

    DebugLog("Expected ImageBase: " + std::to_string(pNTHeaders->OptionalHeader.ImageBase));
    DebugLog("Loaded ImageBase: " + std::to_string((uintptr_t)baseAddress));
    DebugLog("Delta: " + std::to_string(delta));

    PVOID pFirstReloc = (PVOID)((LPBYTE)baseAddress + pNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
    IMAGE_BASE_RELOCATION reloc = *(IMAGE_BASE_RELOCATION*)pFirstReloc;

    while (reloc.SizeOfBlock != 0) {
        int entries = (reloc.SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        WORD* pOffset = (WORD*)((IMAGE_BASE_RELOCATION*)pFirstReloc + 1);

        for (int i = 0; i < entries; i++, pOffset++) {
            WORD type = *pOffset >> 12;
            WORD offset = *pOffset & 0x0FFF;

            if (type == IMAGE_REL_BASED_DIR64) {
                LONG64* pAddressToPatch = (LONG64*)((LPBYTE)baseAddress + reloc.VirtualAddress + offset);
                *pAddressToPatch += delta;
            }
        }

        pFirstReloc = (PVOID)((LPBYTE)pFirstReloc + reloc.SizeOfBlock);
        reloc = *(IMAGE_BASE_RELOCATION*)pFirstReloc;
    }
}

void RegisterExports(PE_BASE_INFO* dllinfo) {
    DWORD eata = dllinfo->pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (eata == 0) {
        return;
    }
    IMAGE_EXPORT_DIRECTORY* ExportDir = (IMAGE_EXPORT_DIRECTORY*)((LPBYTE)dllinfo->baseAddress + eata);

    DWORD* pAddressOfNames = (DWORD*)((LPBYTE)dllinfo->baseAddress + ExportDir->AddressOfNames);
    DWORD* pAddressOfFunctions = (DWORD*)((LPBYTE)dllinfo->baseAddress + ExportDir->AddressOfFunctions);
    WORD* pAddressOfNameOrdinals = (WORD*)((LPBYTE)dllinfo->baseAddress + ExportDir->AddressOfNameOrdinals);

    for (DWORD i = 0; i < ExportDir->NumberOfNames; i++) {
        char* funcName = (char*)((LPBYTE)dllinfo->baseAddress + pAddressOfNames[i]);

        DWORD functionRVA = pAddressOfFunctions[pAddressOfNameOrdinals[i]];
        PVOID pOriginalAddressOfFunction = (PVOID)((LPBYTE)dllinfo->baseAddress + functionRVA);
        FARPROC originalFunctionAddress = (FARPROC)pOriginalAddressOfFunction;
        DebugLog("Function From RegisterExports. Name: " + std::string(funcName) + " Address: " + std::to_string((uintptr_t)originalFunctionAddress) + " " + dllinfo->fullpath);
        dllinfo->functions[funcName] = originalFunctionAddress;
    }
}

bool runTlsCallback(PE_BASE_INFO* peinfo) {
    const DWORD TlsEntryVirtualAddress = peinfo->pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
    DebugLog("TLS Callback entry: " + std::to_string(TlsEntryVirtualAddress));
    if (TlsEntryVirtualAddress == 0) {
        return true;
    }
    const PIMAGE_TLS_DIRECTORY lpImageTLSDirectory = (PIMAGE_TLS_DIRECTORY)((LPBYTE)peinfo->baseAddress + TlsEntryVirtualAddress);
    PIMAGE_TLS_CALLBACK* lpCallbackArray = (PIMAGE_TLS_CALLBACK*)lpImageTLSDirectory->AddressOfCallBacks;

    while (*lpCallbackArray != nullptr) {
        const PIMAGE_TLS_CALLBACK lpImageCallback = *lpCallbackArray;
        DebugLog("Executing TLS callback: " + std::to_string((uintptr_t)lpImageCallback));
        lpImageCallback(peinfo->baseAddress, DLL_PROCESS_ATTACH, nullptr);
        lpCallbackArray++;
    }
    return true;
}

template<typename FunctionType>
bool RunDllFunctions(const std::string& functionName, const std::string& dllPath, LoaderContext* context) {
    auto it = context->loadedDlls.find(dllPath);
    if (it == context->loadedDlls.end()) {
        std::cerr << "Error: DLL not loaded: " << dllPath << "\n";
        return false;
    }

    PE_BASE_INFO* dllInfo = it->second.get();
    auto funcIt = dllInfo->functions.find(functionName);
    if (funcIt != dllInfo->functions.end()) {
        try {
            FunctionType func = (FunctionType)funcIt->second;
            DebugLog("Executing function: " + functionName);
            func();
            return true;
        }
        catch (const std::exception& e) {
            std::cerr << "Error: Exception occurred while executing function " << functionName << ": " << e.what() << "\n";
        }
        catch (...) {
            std::cerr << "Error: Unknown exception occurred while executing function " << functionName << "\n";
        }
        return false;
    }

    std::cerr << "Error: Function " << functionName << " not found in DLL " << dllPath << "\n";
    return false;
}

bool RunDllMainFunction(PE_BASE_INFO* dllInfo) {
    if (!dllInfo) {
        std::cerr << "Invalid DLL information provided." << std::endl;
        return false;
    }

    DebugLog("Running main of: " + dllInfo->fullpath);
    PVOID baseAddress = dllInfo->baseAddress;
    PIMAGE_NT_HEADERS64 pNtHeaders = dllInfo->pNtHeaders;

    PVOID entryPoint = (PVOID)((LPBYTE)baseAddress + pNtHeaders->OptionalHeader.AddressOfEntryPoint);

    DebugLog("Trying to run main dll of: " + dllInfo->fullpath + " on: " + std::to_string((uintptr_t)entryPoint));

    if (entryPoint < baseAddress || entryPoint >= (PVOID)((LPBYTE)baseAddress + pNtHeaders->OptionalHeader.SizeOfImage)) {
        std::cerr << "Invalid entry point address: " << entryPoint << std::endl;
        return false;
    }

    DWORD oldProtect;
    if (!VirtualProtect(entryPoint, sizeof(runnDllMain), PAGE_EXECUTE_READ, &oldProtect)) {
        std::cerr << "Failed to make entry point executable for: " << dllInfo->fullpath << std::endl;
        return false;
    }

    try {
        runnDllMain dllMain = (runnDllMain)entryPoint;
        BOOL result = dllMain((HINSTANCE)baseAddress, DLL_PROCESS_ATTACH, nullptr);

        if (!result) {
            std::cerr << "Failed to run main dll of: " << dllInfo->fullpath << " with error: " << GetLastError() << std::endl;
            return false;
        }
    }
    catch (const std::exception& e) {
        std::cerr << "Exception occurred while running DllMain of: " << dllInfo->fullpath << ": " << e.what() << std::endl;
        return false;
    }
    catch (...) {
        std::cerr << "Unknown exception occurred while running DllMain of: " << dllInfo->fullpath << std::endl;
        return false;
    }

    VirtualProtect(entryPoint, sizeof(runnDllMain), oldProtect, &oldProtect);
    return true;
}

void parseArguments(int argc, char* argv[], bool& debug, std::string& dllFile) {
    for (int i = 1; i < argc; ++i) {
        if (std::string(argv[i]) == "--debug") {
            debug = true;
        }
        else if (std::string(argv[i]) == "--pe") {
            if (i + 1 < argc) {
                dllFile = argv[++i];
            }
            else {
                std::cerr << "Error: Missing argument for --pe\n";
                exit(1);
            }
        }
        else if (dllFile.empty()) {
            dllFile = argv[i];
        }
    }
}

void initializeLoaderContext(bool debug) {
    if (debug) {
        debugout = &std::cout;
    }
    else {
        debugout = nullptr;
    }
}

void loadDll(const std::string& dllFile, LoaderContext* context) {
    size_t fileSize;
    PVOID pPefile = readFile(dllFile.c_str(), &fileSize);

    if (pPefile) {
        DebugLog("Testing directly pe buffer: " + dllFile + " Size: " + std::to_string(fileSize));
        ResolveDependencies(dllFile, nullptr, false, context);
    }
    std::free(pPefile);
}

void handleLoadedDlls(LoaderContext* context) {
    std::set<std::string> handledDlls;

    for (const auto& dllPair : context->loadedDlls) {
        PE_BASE_INFO* dllInfo = dllPair.second.get();
        if (handledDlls.find(dllInfo->fullpath) != handledDlls.end()) {
            continue;
        }
        handledDlls.insert(dllInfo->fullpath);
        BaseRelocation(dllInfo->baseAddress, dllInfo->pNtHeaders);
        FixImports(dllInfo->pNtHeaders, dllInfo->baseAddress, true, context);
        RegisterExports(dllInfo);
        runTlsCallback(dllInfo);
    }
    handledDlls.clear();

    for (const auto& dllPair : context->loadedDlls) {
        PE_BASE_INFO* dllInfo = dllPair.second.get();
        if (handledDlls.find(dllInfo->fullpath) != handledDlls.end()) {
            continue;
        }
        handledDlls.insert(dllInfo->fullpath);

        RunDllMainFunction(dllInfo);
    }
    handledDlls.clear();

    for (const auto& dllPair : context->loadedDlls) {
        PE_BASE_INFO* dllInfo = dllPair.second.get();
        if (handledDlls.find(dllInfo->fullpath) != handledDlls.end()) {
            continue;
        }
        handledDlls.insert(dllInfo->fullpath);

        FixImports(dllInfo->pNtHeaders, dllInfo->baseAddress, false, context);
    }
}

void cleanup(LoaderContext* context) {
    context->loadedDlls.clear();
}




int main(int argc, char* argv[]) {
    bool debug = false;
    std::string dllFile;

    parseArguments(argc, argv, debug, dllFile);

    if (dllFile.empty()) {
        std::cerr << "Usage: " << argv[0] << " --pe <PE path> [--debug]\n";
        return 1;
    }

    initializeLoaderContext(debug);

    LoaderContext context;
    loadDll(dllFile, &context);
    handleLoadedDlls(&context);

    // Example usage:
    // RunDllFunctions<void(*)()>("helloworld", dllFile, &context);

    cleanup(&context);

    return 0;
}


