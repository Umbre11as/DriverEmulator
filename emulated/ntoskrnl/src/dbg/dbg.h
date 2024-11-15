#pragma once

#include "../types.h"

EXPORT ULONG vDbgPrintEx(IN ULONG ComponentId, IN ULONG Level, IN PCSTR Format, IN va_list arglist);
EXPORT ULONG DbgPrintEx(IN ULONG ComponentId, IN ULONG Level, IN PCSTR Format, ...);
EXPORT ULONG DbgPrint(IN PCSTR Format, ...);
