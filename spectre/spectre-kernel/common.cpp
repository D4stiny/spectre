/*
 * This file is subject to the terms and conditions defined in
 * file 'LICENSE', which is part of this source code package.
 *
 * COPYRIGHT Bill Demirkapi 2020
 */
#include "common.h"

void* __cdecl operator new(size_t size, POOL_TYPE pool, ULONG tag) {
	PVOID newAddress;
	
	newAddress = ExAllocatePoolWithTag(pool, size, tag);
	//
	// Remove remenants from previous use.
	//
	if (newAddress)
	{
		memset(newAddress, 0, size);
	}
	return newAddress;
}

void __cdecl operator delete(void* p, unsigned __int64) {
	ExFreePool(p);
}