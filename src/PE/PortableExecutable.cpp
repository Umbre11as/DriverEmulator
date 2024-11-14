#include "PortableExecutable.h"

PortableExecutable::PortableExecutable(IN std::vector<BYTE> Buffer) : Buffer(std::move(Buffer)) {
    DosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(this->Buffer.data());
    NtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<ULONGPTR>(DosHeader) + DosHeader->e_lfanew);
}

PBYTE PortableExecutable::Map() const {
    const IMAGE_OPTIONAL_HEADER optionalHeader = NtHeaders->OptionalHeader;
    auto mapped = new BYTE[optionalHeader.SizeOfImage];
    memcpy(mapped, DosHeader, optionalHeader.SizeOfHeaders);

    const auto sections = IMAGE_FIRST_SECTION(NtHeaders);
    for (WORD i = 0; i < NtHeaders->FileHeader.NumberOfSections; i++) {
        if (const IMAGE_SECTION_HEADER sectionHeader = sections[i]; sectionHeader.SizeOfRawData)
            memcpy(mapped + sectionHeader.VirtualAddress, reinterpret_cast<PBYTE>(DosHeader) + sectionHeader.PointerToRawData, sectionHeader.SizeOfRawData);
    }

    return mapped;
}

std::vector<Import> PortableExecutable::Imports() const {
    std::vector<Import> imports{};

    DWORD importsRVA = NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (!importsRVA)
        goto end;

    for (auto importDescriptor = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(ResolveRVA(importsRVA)); importDescriptor->Characteristics; importDescriptor++) {
        auto dllName = reinterpret_cast<PCSTR>(ResolveRVA(importDescriptor->Name));

        for (auto thunkData = reinterpret_cast<PIMAGE_THUNK_DATA>(ResolveRVA(importDescriptor->FirstThunk)); thunkData->u1.AddressOfData; thunkData++) {
            if (auto importByName = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(ResolveRVA(thunkData->u1.AddressOfData))) {
                imports.push_back({
                    dllName,
                    importByName->Name,
                    thunkData
                });
            }
        }
    }

end:
    return imports;
}

ULONGPTR PortableExecutable::ResolveRVA(IN UINT RVA) const {
    const auto sections = IMAGE_FIRST_SECTION(NtHeaders);
    for (WORD i = 0; i < NtHeaders->FileHeader.NumberOfSections; i++) {
        if (const IMAGE_SECTION_HEADER sectionHeader = sections[i]; RVA >= sectionHeader.VirtualAddress && RVA <= sectionHeader.VirtualAddress + sectionHeader.Misc.VirtualSize)
            return reinterpret_cast<ULONG_PTR>(DosHeader) + (sectionHeader.PointerToRawData + RVA - sectionHeader.VirtualAddress);
    }

    return 0;
}
