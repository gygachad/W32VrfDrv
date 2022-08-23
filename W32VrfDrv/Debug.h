#pragma once

#define _DEBUG

#ifdef _DEBUG
#define W32VrfDbgPrint(...) DbgPrintEx(__VA_ARGS__);
#else
#define W32VrfDbgPrint(...)
#endif