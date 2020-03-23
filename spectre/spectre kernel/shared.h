/*
 * This file is subject to the terms and conditions defined in
 * file 'LICENSE', which is part of this source code package.
 *
 * COPYRIGHT Bill Demirkapi 2020
 */
#pragma once
#if _KERNEL_MODE == 1
#include <fltKernel.h>
#else
#include <Windows.h>
#endif

//
// The magic value to look for in packets. Indicates a malicious packet.
//
#define PACKET_MAGIC 0xDEADBEEF

