#pragma once

#include <fstream>
#include <vector>

namespace Utils::File {
    static std::vector<BYTE> Read(IN PCSTR Path) {
        std::ifstream inputFileStream(Path, std::ios::binary | std::ios::ate);
        if (!inputFileStream.is_open())
            return {};

        const std::streamsize size = inputFileStream.tellg();
        inputFileStream.seekg(0, std::ios::beg);

        std::vector<BYTE> buffer(size);
        inputFileStream.read(reinterpret_cast<char*>(buffer.data()), size);

        inputFileStream.close();
        return buffer;
    }

    static void Write(IN PCSTR Path, IN std::vector<BYTE> Buffer) {
        std::ofstream outputFileStream(Path, std::ios::binary);
        outputFileStream.write(reinterpret_cast<char*>(Buffer.data()), static_cast<std::streamsize>(Buffer.size()));
        outputFileStream.close();
    }
}
