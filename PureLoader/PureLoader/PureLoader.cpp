#include <iostream>
#include <fstream>
#include <cstdlib>
#include "windows.h"
#include <map>
#include <set>
#include <vector>
#include <sstream>
#include <algorithm>
#include <cstdio>



using runnDllMain = BOOL(WINAPI*)(HINSTANCE dll, DWORD reason, LPVOID reserved);


struct PE_BASE_INFO {
    std::string fullpath;
    PVOID baseAddress;
    PIMAGE_NT_HEADERS64 pNtHeaders;
    std::map<std::string, FARPROC> functions;
};




std::map<std::string, PE_BASE_INFO*> loadedDlls;
std::set <std::string> readedDlls;



std::ostream* debugout;

class NullBuffer : public std::streambuf {
public:
    int overflow(int c) { return c; }
};


class NullStream : public std::ostream {
public:
    NullStream() : std::ostream(&nullBuffer) {}
private:
    NullBuffer nullBuffer;
};



void stringToLower(std::string& str) {
    std::transform(str.begin(), str.end(), str.begin(), [](unsigned char c) { return std::tolower(c); });
}


PVOID readFile(const char* filename, size_t* fileSize) {
    std::ifstream file(filename, std::ios::binary | std::ios::ate);
    if (!file) return nullptr;

    *fileSize = file.tellg();
    void* buffer = std::malloc(*fileSize);
    if (!buffer) return nullptr;

    file.seekg(0, std::ios::beg);
    file.read(static_cast<char*>(buffer), *fileSize);
    file.close();

    return buffer;
}

PE_BASE_INFO* findDllInfoByPath(const std::string& path) {
    for (const auto& pair : loadedDlls) {
        if (pair.second->fullpath == path) {
            return pair.second;
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
    *debugout << "Size Of image: " << std::hex << pNTHeaders->OptionalHeader.SizeOfImage << "\n";

    return VirtualAlloc(0, pNTHeaders->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
}

void GetHeaders(PVOID pDllfile, PIMAGE_DOS_HEADER* pDOSHeader, PIMAGE_NT_HEADERS64* pNTHeaders) {
    *pDOSHeader = (PIMAGE_DOS_HEADER)pDllfile;
    *pNTHeaders = (PIMAGE_NT_HEADERS64)((LPBYTE)pDllfile + (*pDOSHeader)->e_lfanew);
}


void WriteHeaders(PVOID pDllfile, PVOID baseAddress, PIMAGE_NT_HEADERS64 pNTHeaders) {
    *debugout << "Size of headers: " << std::hex << pNTHeaders->OptionalHeader.SizeOfHeaders << "\n";
    memcpy(baseAddress, pDllfile, pNTHeaders->OptionalHeader.SizeOfHeaders);
}



void WriteSections(PVOID baseAddress, PVOID pDllfile, PIMAGE_DOS_HEADER pDOSHeader, PIMAGE_NT_HEADERS64 pNTHeaders) {

    for (int i = 0; i < pNTHeaders->FileHeader.NumberOfSections; i++) {
        PIMAGE_SECTION_HEADER pSectionHeader =
            (PIMAGE_SECTION_HEADER)((LPBYTE)baseAddress + pDOSHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS64)
                + (i * sizeof(IMAGE_SECTION_HEADER)));

        *debugout << pSectionHeader->Name << "\n";
        *debugout << "Virtual Address: " << std::hex << pSectionHeader->VirtualAddress << "\n";
        *debugout << "Raw offset: " << std::hex << pSectionHeader->PointerToRawData << "\n";
        *debugout << "Size of raw data: " << std::hex << pSectionHeader->SizeOfRawData << "\n";
        *debugout << "Virtual Size: " << std::hex << pSectionHeader->Misc.VirtualSize << "\n";
        if (pSectionHeader->SizeOfRawData > 0) {
            *debugout << "Writing section to: " << std::hex << (PVOID)((LPBYTE)baseAddress + pSectionHeader->VirtualAddress) << "\n";
            memcpy((PVOID)((LPBYTE)baseAddress + pSectionHeader->VirtualAddress),
                (PVOID)((LPBYTE)pDllfile + pSectionHeader->PointerToRawData),
                pSectionHeader->SizeOfRawData);

        }
        *debugout << "\n";
    }
}

FARPROC getFunctionAddress(const std::string& dllNameStr, const std::string& funcNameStr) {
    auto dllIt = loadedDlls.find(dllNameStr);
    if (dllIt != loadedDlls.end()) {
        PE_BASE_INFO* dllInfo = dllIt->second;
        auto funcIt = dllInfo->functions.find(funcNameStr);
        if (funcIt != dllInfo->functions.end()) {
            return funcIt->second;
        }
    }
    return nullptr;
}



bool FixImports(PIMAGE_NT_HEADERS64 pNTHeaders, PVOID baseAddress, bool isinitial) {
    if (pNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size > 0) {
        PVOID importPtr = (PVOID)((LPBYTE)baseAddress + pNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
        IMAGE_IMPORT_DESCRIPTOR ImportDesc = *(IMAGE_IMPORT_DESCRIPTOR*)importPtr;
        while (ImportDesc.Name != 0) {
            char* dllName = (char*)((PVOID)((LPBYTE)baseAddress + ImportDesc.Name));
            std::string dllNameStr(dllName);

            PVOID pOft = (PVOID)((LPBYTE)baseAddress + ImportDesc.OriginalFirstThunk);
            PVOID pfirstthunk = (PVOID)((LPBYTE)baseAddress + ImportDesc.FirstThunk);
            IMAGE_THUNK_DATA64 thunk = *(IMAGE_THUNK_DATA64*)pOft;
            while (thunk.u1.Function < 0x8000000000000000 && thunk.u1.Function != 0) {
                LPBYTE pNameAddress = (LPBYTE)baseAddress + thunk.u1.AddressOfData;
                char* funcName = (char*)(pNameAddress + 2);
                std::string funcNamestr(funcName);
                *debugout << "  Function name: " << funcNamestr << "\n";
                FARPROC functionAddress;
                if (isinitial) {
                    functionAddress = GetProcAddress(LoadLibraryA(dllNameStr.c_str()), funcNamestr.c_str());
                }
                else {
                    functionAddress = getFunctionAddress(dllNameStr, funcNamestr);
                }

                if (functionAddress) {
                    *debugout << "      Function Address: " << std::hex << functionAddress << "\n";
                    *(FARPROC*)pfirstthunk = functionAddress;
                }
                else {
                    std::cerr << "Unable to loacte function: " << funcNamestr << " in cutome mapped functions\n";
                    exit(12);
                    return FALSE;
                }
                pfirstthunk = (PVOID)(((LPBYTE)pfirstthunk) + 8);
                pOft = (PVOID)(((LPBYTE)pOft) + sizeof(IMAGE_THUNK_DATA64));
                thunk = *(IMAGE_THUNK_DATA64*)pOft;
            }

            importPtr = (PVOID)((LPBYTE)importPtr + sizeof(IMAGE_IMPORT_DESCRIPTOR));
            ImportDesc = *(IMAGE_IMPORT_DESCRIPTOR*)importPtr;
        }
    }
    return TRUE;
}



void ResolveDependencies(const std::string& dllName, const std::string test, PVOID pPefile) {
    *debugout << test << "\n";

    *debugout << "Resolving dependencies for: " << dllName << "\n";

    if (loadedDlls.find(dllName) != loadedDlls.end()) {
        *debugout << "Already resolved: " << dllName << "\n\n\n";
        return;
    }


    const std::string dllPath = GetFullPathForDll(dllName);
    PE_BASE_INFO* foundDllInfo = findDllInfoByPath(dllPath);
    if (foundDllInfo != nullptr) {
        *debugout << "Dll Was alredy loaded by is path: " << dllPath << " updating name: " << dllName << "\n";
        loadedDlls[dllName] = foundDllInfo;
        return;
    }

    PVOID pDllfile;
    if (pPefile == nullptr) {
        *debugout << "Reading data for :" << dllPath << "\n";
        size_t fileSize;
        pDllfile = readFile(dllPath.c_str(), &fileSize);
        *debugout << "Successfully read DLL: " << dllPath << ", Size: " << fileSize << " bytes" << "\n";
        if (!pDllfile) {
            std::cerr << "Failed to read the DLL: " << dllPath << "\n";
            return;
        }
    }
    else
    {
        pDllfile = pPefile;
    }


    PIMAGE_DOS_HEADER pDOSHeader;
    PIMAGE_NT_HEADERS64 pNTHeaders;
    GetHeaders(pDllfile, &pDOSHeader, &pNTHeaders);
    if (pNTHeaders->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
        std::cerr << dllPath << " is not x64" << "\n";
    }

    PVOID baseAddress = GetFixedBaseAddress(pNTHeaders);
    *debugout << "Allocated base address: " << baseAddress << " for DLL: " << dllPath << "\n";

    WriteHeaders(pDllfile, baseAddress, pNTHeaders);
    WriteSections(baseAddress, pDllfile, pDOSHeader, pNTHeaders);

    GetHeaders(baseAddress, &pDOSHeader, &pNTHeaders);

    if (!baseAddress) {
        std::cerr << "Unable to allocate base address for: " << dllPath << "\n";
        std::free(pDllfile);
        return;
    }


    PE_BASE_INFO* dllInfo = new PE_BASE_INFO();
    dllInfo->baseAddress = baseAddress;
    dllInfo->pNtHeaders = pNTHeaders;
    dllInfo->fullpath = dllPath;
    loadedDlls[dllName] = dllInfo;


    if (pNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size > 0) {
        PVOID importPtr = (PVOID)((LPBYTE)baseAddress + pNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
        IMAGE_IMPORT_DESCRIPTOR ImportDesc = *(IMAGE_IMPORT_DESCRIPTOR*)importPtr;

        while (ImportDesc.Name != 0) {
            char* dllName = (char*)((PVOID)((LPBYTE)baseAddress + ImportDesc.Name));
            std::string fullPath = GetFullPathForDll(dllName);

            if (fullPath.empty()) {
                std::cerr << "Skipping API set DLL: " << dllName << "\n";
                std::free(pDllfile);
                return;
            }
            else {
                *debugout << "Found imported DLL: " << dllName << ", Full path: " << fullPath << "\n";
                std::stringstream ss;
                ss << "Recorsion called from the dll " << dllInfo->fullpath << " to " << dllName << "\n";
                ResolveDependencies(dllName, ss.str(), nullptr);
            }
            importPtr = (PVOID)((LPBYTE)importPtr + sizeof(IMAGE_IMPORT_DESCRIPTOR));
            ImportDesc = *(IMAGE_IMPORT_DESCRIPTOR*)importPtr;
        }
    }
    else {
        *debugout << "DLL " << dllPath << " has no imports." << "\n";
    }
    std::free(pDllfile);
    *debugout << "Freed memory for DLL: " << dllPath << "\n\n";
}



void BaseRelocation(PVOID baseAddress, PIMAGE_NT_HEADERS64 pNTHeaders) {
    LONG64 delta = (LONG64)baseAddress - (LONG64)pNTHeaders->OptionalHeader.ImageBase;

    *debugout << "Expected ImageBase: " << std::hex << pNTHeaders->OptionalHeader.ImageBase << "\n";
    *debugout << "Loaded ImageBase: " << std::hex << baseAddress << "\n";
    *debugout << "Delta: " << std::hex << delta << "\n";

    PVOID pFirstReloc = (PVOID)((LPBYTE)baseAddress + pNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
    DWORD allRelocSize = pNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;

    IMAGE_BASE_RELOCATION reloc = *(IMAGE_BASE_RELOCATION*)pFirstReloc;

    while (reloc.SizeOfBlock != 0)
    {
        int entries = (reloc.SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

        WORD* pOffset = (WORD*)((IMAGE_BASE_RELOCATION*)pFirstReloc + 1);

        for (int i = 0; i < entries; i++, pOffset++)
        {
            WORD type = *pOffset >> 12;
            WORD offset = *pOffset & 0x0FFF;

            if (type == IMAGE_REL_BASED_DIR64)
            {
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
    *debugout << "Export Address Table Address: " << std::hex << eata << "\n";
    IMAGE_EXPORT_DIRECTORY* ExportDir = (IMAGE_EXPORT_DIRECTORY*)((LPBYTE)dllinfo->baseAddress + eata);
    *debugout << "NumberOfNames: " << ExportDir->NumberOfNames << "\n";

    DWORD* pAddressOfNames = (DWORD*)((LPBYTE)dllinfo->baseAddress + ExportDir->AddressOfNames);
    *debugout << "pAddressOfNames: " << pAddressOfNames << std::hex << "\n";

    DWORD* pAddressOfFunctions = (DWORD*)((LPBYTE)dllinfo->baseAddress + ExportDir->AddressOfFunctions);
    *debugout << "pAddressOfFunctions: " << pAddressOfFunctions << std::hex << "\n";

    WORD* pAddressOfNameOrdinals = (WORD*)((LPBYTE)dllinfo->baseAddress + ExportDir->AddressOfNameOrdinals);
    *debugout << "pAddressOfNameOrdinals: " << pAddressOfNameOrdinals << std::hex << "\n";

    for (DWORD i = 0; i < ExportDir->NumberOfNames; i++) {
        char* funcName = (char*)((LPBYTE)dllinfo->baseAddress + pAddressOfNames[i]);

        DWORD functionRVA = pAddressOfFunctions[pAddressOfNameOrdinals[i]];
        PVOID pOriginalAddressOfFunction = (PVOID)((LPBYTE)dllinfo->baseAddress + functionRVA);
        FARPROC originalFunctionAddress = (FARPROC)(pOriginalAddressOfFunction);
        *debugout << "Function From RegisterExports. Name: " << funcName << " Address: " << originalFunctionAddress << std::hex << dllinfo->fullpath << "\n";
        dllinfo->functions[funcName] = originalFunctionAddress;
    }
}



bool runTlsCallback(PE_BASE_INFO* peinfo) {
    const DWORD TlsEntryVirtualAddress = peinfo->pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
    *debugout << "TLS Calback entry: " << TlsEntryVirtualAddress << "\n";
    if (TlsEntryVirtualAddress == 0) {
        return true;
    }
    const PIMAGE_TLS_DIRECTORY lpImageTLSDirectory = (PIMAGE_TLS_DIRECTORY)((LPBYTE)peinfo->baseAddress + TlsEntryVirtualAddress);
    PIMAGE_TLS_CALLBACK* lpCallbackArray = (PIMAGE_TLS_CALLBACK*)lpImageTLSDirectory->AddressOfCallBacks;

    *debugout << "Address Of CallBacks: " << lpCallbackArray << std::hex << "\n";
    while (*lpCallbackArray != nullptr)
    {
        const PIMAGE_TLS_CALLBACK lpImageCallback = *lpCallbackArray;
        *debugout << "Executing current Calback: " << lpImageCallback << std::hex << "\n";
        lpImageCallback(peinfo->baseAddress, DLL_PROCESS_ATTACH, nullptr);
        lpCallbackArray++;
    }
}



template<typename FunctionType>
bool RunDllFunctions(const std::string& functionName, const std::string& dllPath) {
    auto it = loadedDlls.find(dllPath);
    if (it == loadedDlls.end()) {
        std::cerr << "Error: DLL not loaded: " << dllPath << "\n";
        return false;
    }

    PE_BASE_INFO* dllPair = it->second;
    for (const auto& funcPair : dllPair->functions) {
        *debugout << "    Function Name: " << funcPair.first << "\n";
        *debugout << "    Function Address: " << funcPair.second << "\n";

        if (funcPair.first == functionName) {
            try {
                PVOID pOriginalAddressOfFunction = funcPair.second;
                FunctionType func = reinterpret_cast<FunctionType>(pOriginalAddressOfFunction);
                *debugout << "    Executing function: " << functionName << "\n";
                func();
                return true;
            }
            catch (const std::exception& e) {
                std::cerr << "    Error: Exception occurred while executing function " << functionName << ": " << e.what() << "\n";
            }
            catch (...) {
                std::cerr << "    Error: Unknown exception occurred while executing function " << functionName << "\n";
            }
            return false;
        }
    }

    std::cerr << "    Error: Function " << functionName << " not found in DLL " << dllPath << "\n";
    return false;
}


bool RunDllMainFunction(PE_BASE_INFO* dllInfo) {
    if (!dllInfo) {
        std::cerr << "Invalid DLL information provided." << std::endl;
        return false;
    }

    *debugout << "Running main of: " << dllInfo->fullpath << std::endl;
    PVOID baseAddress = dllInfo->baseAddress;
    PIMAGE_NT_HEADERS64 pNtHeaders = dllInfo->pNtHeaders;

    PVOID entryPoint = (PVOID)((LPBYTE)baseAddress + pNtHeaders->OptionalHeader.AddressOfEntryPoint);

    *debugout << "Trying to run main dll of: " << dllInfo->fullpath << " on: " << entryPoint << std::endl;

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




int main(int argc, char* argv[]) {

    bool debug = false;
    const char* dllFile = nullptr;


    for (int i = 1; i < argc; ++i) {
        if (std::string(argv[i]) == "--debug") {
            debug = true;
        }
        else if (std::string(argv[i]) == "--pe") {
            dllFile = argv[i + 1];
        }
        else if (!dllFile) {
            dllFile = argv[i];
        }
    }

    if (!dllFile) {
        std::cerr << "Usage: " << " --pe <PE path> [--debug]\n";
        return 1;
    }


    debugout = debug ? &std::cout : new NullStream();

    size_t fileSize;


    PVOID pPefile = readFile(dllFile, &fileSize);

    *debugout << "Testing directly pe buffer: " << dllFile << " Size: " << fileSize << "\n";

    ResolveDependencies(dllFile, "", nullptr);
    std::set<std::string> handeledDlls;

    handeledDlls.clear();
    for (const auto& dllPair : loadedDlls) {
        if (handeledDlls.find(dllPair.second->fullpath) != handeledDlls.end()) {
            continue;
        }
        handeledDlls.insert(dllPair.second->fullpath);
        BaseRelocation(dllPair.second->baseAddress, dllPair.second->pNtHeaders);
        FixImports(dllPair.second->pNtHeaders, dllPair.second->baseAddress, true);
        RegisterExports(dllPair.second);
        runTlsCallback(dllPair.second);
    }
    handeledDlls.clear();

    for (const auto& dllPair : loadedDlls) {
        if (handeledDlls.find(dllPair.second->fullpath) != handeledDlls.end()) {
            continue;
        }
        handeledDlls.insert(dllPair.second->fullpath);

        RunDllMainFunction(dllPair.second);
    }
    handeledDlls.clear();

    for (const auto& dllPair : loadedDlls) {
        if (handeledDlls.find(dllPair.second->fullpath) != handeledDlls.end()) {
            continue;
        }
        handeledDlls.insert(dllPair.second->fullpath); 

        FixImports(dllPair.second->pNtHeaders, dllPair.second->baseAddress, false); 

    }
    // Example usage
    // RunDllFunctions<void(*)()>("helloworld", dllFile);

    return 0;
}