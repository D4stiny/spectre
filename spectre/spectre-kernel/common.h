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
#define DBGPRINT_NONEWLINE(msg, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, msg, __VA_ARGS__)
#define DEFINE_TAG(tag) tag
#else
#define DBGPRINT(x, ...)
#define DBGPRINT_NONEWLINE(x, ...)
//
// The default tag used in ExAllocatePool.
// If we're compiling for release, let's not use tags specifically associated with the Spectre rootkit.
//
#define DEFINE_TAG(tag) 'enoN'
#endif

void* __cdecl operator new(size_t size, POOL_TYPE pool, ULONG tag = 0);
void __cdecl operator delete(void* p, unsigned __int64);
#endif
#include "shared.h"

#define FlagOn(_F,_SF) ((_F) & (_SF))

#define SYSTEMTIME_TO_MILLISECONDS(systemtime) (systemtime.QuadPart / 10000)
#define MILLISECONDS_TO_SYSTEMTIME(milliseconds) (milliseconds * 10000)

#define ALIGN(x,align)      (((ULONG)(x)+(align)-1UL)&(~((align)-1UL)))

#define MAX_PATH 260