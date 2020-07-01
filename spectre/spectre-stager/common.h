#pragma once
#include <Windows.h>
#include <cstdio>
#include <fstream>
#include <string>
#include <time.h>
#include "xorstr.hpp"

#define NT_SUCCESS(x) ((x)>=0)
#define STATUS_SUCCESS 0
#define STATUS_FAILED 1

#define RCAST reinterpret_cast
#define SCAST static_cast
#define CCAST const_cast

#ifdef _DEBUG
#define DBGPRINT(msg, ...) printf(msg"\n", __VA_ARGS__)
#else
#define DBGPRINT(x, ...)
#endif