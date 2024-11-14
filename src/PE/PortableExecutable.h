#pragma once

#include <Windows.h>
#include <vector>

struct Import {
    PCSTR DllName;
    PCSTR Name;
    PIMAGE_THUNK_DATA ThunkData;
};

class PortableExecutable {
public:
    explicit PortableExecutable(IN std::vector<BYTE> Buffer);

    ~PortableExecutable() = default;
public:
    [[nodiscard]] PBYTE Map() const;
    [[nodiscard]] std::vector<Import> Imports() const;
private:
    [[nodiscard]] ULONGPTR ResolveRVA(IN UINT RVA) const;
private:
    std::vector<BYTE> Buffer;
public:
    PIMAGE_DOS_HEADER DosHeader;
    PIMAGE_NT_HEADERS NtHeaders;
};
