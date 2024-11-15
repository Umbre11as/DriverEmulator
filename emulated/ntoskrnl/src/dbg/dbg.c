#include "dbg.h"

EXPORT ULONG vDbgPrintEx(IN ULONG ComponentId, IN ULONG Level, IN PCSTR Format, IN va_list arglist) {
    char buffer[1024];
    int result = vsnprintf_s(buffer, sizeof(buffer), _TRUNCATE, Format, arglist);
    fprintf(Level == 0 ? stdout : stderr, "[vDbgPrintEx]: %s", buffer);

    return result;
}

EXPORT ULONG DbgPrintEx(IN ULONG ComponentId, IN ULONG Level, IN PCSTR Format, ...) {
    va_list args;
    va_start(args, Format);

    ULONG result = vDbgPrintEx(ComponentId, Level, Format, args);

    va_end(args);
    return result;
}

EXPORT ULONG DbgPrint(IN PCSTR Format, ...) {
    va_list args;
    va_start(args, Format);

    ULONG result = vDbgPrintEx(0, 0, Format, args);

    va_end(args);
    return result;
}
