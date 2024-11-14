#include <Windows.h>
#include <stdio.h>
#include <stdarg.h>

#define EXPORT __declspec(dllexport)

EXPORT ULONG DbgPrintEx(ULONG ComponentId, ULONG Level, PCSTR Format, ...) {
    va_list args;
    va_start(args, Format);

    char buffer[1024];
    int result = vsnprintf_s(buffer, sizeof(buffer), _TRUNCATE, Format, args);
    fprintf(Level == 0 ? stdout : stderr, "[DbgPrint]: %s", buffer);

    va_end(args);
    return result;
}

EXPORT ULONG DbgPrint(IN PCSTR Format, ...) {
    return DbgPrintEx(0, 0, Format);
}
