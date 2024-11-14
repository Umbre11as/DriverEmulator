#include "PortableExecutable.h"

PortableExecutable::PortableExecutable(IN std::vector<BYTE>& Buffer) : Buffer(Buffer) {
    DosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(Buffer.data());
    NtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<ULONGPTR>(DosHeader) + DosHeader->e_lfanew);
}

PBYTE PortableExecutable::Map() {
    PBYTE data = Buffer.data();

    const IMAGE_OPTIONAL_HEADER optionalHeader = NtHeaders->OptionalHeader;
    auto mapped = new BYTE[optionalHeader.SizeOfImage];
    memcpy(mapped, data, optionalHeader.SizeOfHeaders);

    const auto sections = IMAGE_FIRST_SECTION(NtHeaders);
    for (WORD i = 0; i < NtHeaders->FileHeader.NumberOfSections; i++) {
        if (const IMAGE_SECTION_HEADER sectionHeader = sections[i]; sectionHeader.SizeOfRawData)
            memcpy(mapped + sectionHeader.VirtualAddress, data + sectionHeader.PointerToRawData, sectionHeader.SizeOfRawData);
    }

    return mapped;
}
