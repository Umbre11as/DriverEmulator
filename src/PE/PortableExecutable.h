#pragma once

#include <Windows.h>
#include <vector>

class PortableExecutable {
public:
    explicit PortableExecutable(IN std::vector<BYTE>& Buffer);
public:
    PBYTE Map();
private:
    std::vector<BYTE> Buffer;
public:
    PIMAGE_DOS_HEADER DosHeader;
    PIMAGE_NT_HEADERS NtHeaders;
};
