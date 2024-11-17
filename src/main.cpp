#include <iostream>
#include <unordered_map>
#include "Utils/FileUtils.h"
#include "PE/PortableExecutable.h"

using DriverEntryFn = NTSTATUS(*)(PVOID, PVOID);

std::unordered_map<std::string, std::string> modulePerModule {
    { "ntoskrnl.exe", "ntoskrnl.dll" },
    { "fltmgr.sys", "fltmgr.dll" }
};

int main() {
    std::vector<BYTE> buffer = Utils::File::Read(R"(..\environment\HelloWorld.sys)");
    if (buffer.empty()) {
        std::cerr << "File not found" << std::endl;
        return 1;
    }
    PortableExecutable pe(buffer);

    PBYTE mapped = pe.Map();
    bool allResolved = true;
    if (DWORD importsRVA = pe.NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress) {
        for (auto importDescriptor = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(mapped + importsRVA); importDescriptor->Characteristics; importDescriptor++) {
            auto dllName = reinterpret_cast<PCSTR>(mapped + importDescriptor->Name);
            HMODULE module = LoadLibrary(modulePerModule[std::string(dllName)].c_str());

            for (auto thunkData = reinterpret_cast<PIMAGE_THUNK_DATA>(mapped + importDescriptor->FirstThunk); thunkData->u1.AddressOfData; thunkData++) {
                if (auto importByName = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(mapped + thunkData->u1.AddressOfData)) {
                    thunkData->u1.Function = reinterpret_cast<ULONGPTR>(GetProcAddress(module, importByName->Name));
                    if (!thunkData->u1.Function) {
                        std::cerr << "Unresolved import: " << importByName->Name << std::endl;
                        allResolved = false;
                    }
                }
            }
        }
    }
    if (!allResolved)
        std::cerr << "Not all functions are resolved" << std::endl;

    DWORD oldProtect = 0;
    VirtualProtect(mapped, pe.NtHeaders->OptionalHeader.SizeOfImage, PAGE_EXECUTE_READWRITE, &oldProtect);

    const auto entryPoint = reinterpret_cast<DriverEntryFn>(mapped + pe.NtHeaders->OptionalHeader.AddressOfEntryPoint);
    const NTSTATUS status = entryPoint(nullptr, nullptr); // Like driver is manual mapped - no driver object and registry path
    std::cout << "Exited with code: 0x" << std::hex << status << std::endl;

    return 0;
}
