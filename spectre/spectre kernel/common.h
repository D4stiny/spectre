/*
 * This file is subject to the terms and conditions defined in
 * file 'LICENSE', which is part of this source code package.
 *
 * COPYRIGHT Bill Demirkapi 2020
 */
#pragma once
#if _KERNEL_MODE == 1
#include "ntdef.h"

#ifdef _DEBUG
#define DBGPRINT(msg, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, msg"\n", __VA_ARGS__)
#else
#define DBGPRINT(x, ...)
#endif

void* __cdecl operator new(size_t size, POOL_TYPE pool, ULONG tag = 0);
void __cdecl operator delete(void* p, unsigned __int64);
#endif
#include "shared.h"

#define RCAST reinterpret_cast
#define SCAST static_cast
#define CCAST const_cast

#define FlagOn(_F,_SF) ((_F) & (_SF))