#include <iostream>
#include "Utils/FileUtils.h"
#include "PE/PortableExecutable.h"

using DriverEntryFn = NTSTATUS(*)(PVOID, PVOID);

int main() {
    std::vector<BYTE> buffer = Utils::File::Read(R"(..\environment\HelloWorld.sys)");
    PortableExecutable pe(buffer);

    PBYTE mapped = pe.Map();
    HMODULE ntoskrnl = LoadLibrary("ntoskrnl.dll");

    if (DWORD importsRVA = pe.NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress) {
        for (auto importDescriptor = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(mapped + importsRVA); importDescriptor->Characteristics; importDescriptor++) {
            // ReSharper disable CppTooWideScopeInitStatement
            auto dllName = reinterpret_cast<PCSTR>(mapped + importDescriptor->Name);
            if (strcmp(dllName, "ntoskrnl.exe") != 0) {
                std::cerr << "Unsupported target module: " << dllName << std::endl;
                break;
            }
            // ReSharper restore CppTooWideScopeInitStatement

            for (auto thunkData = reinterpret_cast<PIMAGE_THUNK_DATA>(mapped + importDescriptor->FirstThunk); thunkData->u1.AddressOfData; thunkData++) {
                if (auto importByName = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(mapped + thunkData->u1.AddressOfData))
                    thunkData->u1.Function = reinterpret_cast<ULONGPTR>(GetProcAddress(ntoskrnl, importByName->Name));
            }
        }
    }

    DWORD oldProtect = 0;
    VirtualProtect(mapped, pe.NtHeaders->OptionalHeader.SizeOfImage, PAGE_EXECUTE_READWRITE, &oldProtect);

    const auto entryPoint = reinterpret_cast<DriverEntryFn>(mapped + pe.NtHeaders->OptionalHeader.AddressOfEntryPoint);
    const NTSTATUS status = entryPoint(nullptr, nullptr); // Like driver is manual mapped - no driver object and registry path
    std::cout << "Exited with code: 0x" << std::hex << status << std::endl;

    return 0;
}
