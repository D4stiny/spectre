/*
 * This file is subject to the terms and conditions defined in
 * file 'LICENSE', which is part of this source code package.
 *
 * COPYRIGHT Bill Demirkapi 2020
 */
#pragma once
#include <winsock2.h>
#include <ws2tcpip.h>
#include <Windows.h>
#include <string>
#include <map>
#include <vector>
#include <shared.h>
#include <fstream>
#include <streambuf>
#include <time.h>
#include <locale>
#include <codecvt>
#include <string>
#include <iostream>
#include <regex>
#include <sstream>

#pragma comment (lib, "ws2_32.lib")

#ifdef _DEBUG
#define DBGPRINT(msg, ...) printf(msg"\n", __VA_ARGS__)
#else
#define DBGPRINT(x, ...)
#endif