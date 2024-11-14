#include <iostream>
#include "Utils/FileUtils.h"
#include "PE/PortableExecutable.h"

using DriverEntryFn = NTSTATUS(*)(PVOID, PVOID);

int main() {
    std::vector<BYTE> buffer = Utils::File::Read(R"(environment\Nothing.sys)");
    PortableExecutable pe(buffer);

    PBYTE mapped = pe.Map();

    DWORD oldProtect = 0;
    VirtualProtect(mapped, pe.NtHeaders->OptionalHeader.SizeOfImage, PAGE_EXECUTE_READWRITE, &oldProtect);

    const auto entryPoint = reinterpret_cast<DriverEntryFn>(mapped + pe.NtHeaders->OptionalHeader.AddressOfEntryPoint);
    const NTSTATUS status = entryPoint(nullptr, nullptr); // Like driver is manual mapped - no driver object and registry path
    std::cout << "Exited with code: 0x" << std::hex << status << std::endl;

    return 0;
}
