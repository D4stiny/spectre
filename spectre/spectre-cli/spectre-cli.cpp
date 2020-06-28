/*
 * This file is subject to the terms and conditions defined in
 * file 'LICENSE', which is part of this source code package.
 *
 * COPYRIGHT Bill Demirkapi 2020
 */
#include "common.h"
#include "ModuleManager.h"
#include "SpectreClient.h"
#include "Configuration.h"

int main(int argc, char* argv[])
{
    INT result;
    WSADATA wsaData;
    ModuleManager moduleManager;

	//
	// Initialize the WinSock library.
	//
    result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != 0) {
        DBGPRINT("main: WSAStartup failed with error %i.", WSAGetLastError());
        return FALSE;
    }
	
    return moduleManager.DispatchToModule(argc, argv);
}