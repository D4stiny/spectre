/*
 * This file is subject to the terms and conditions defined in
 * file 'LICENSE', which is part of this source code package.
 *
 * COPYRIGHT Bill Demirkapi 2020
 */
#include <Windows.h>
#include <iostream>
#include <time.h>
#include <sstream>
#include <iomanip>
#include <vector>
#include <fstream>

#define RCAST reinterpret_cast
#define SCAST static_cast
#define CCAST const_cast

CONST CHAR HeaderPrefixFormat[] = "#pragma once\n\n#define XOR_KEY 0x%X\n\nunsigned char %s_data[%i] = {";
CONST CHAR HeaderSuffixFormat[] = "\n};";


INT
main (
	INT argc,
	CHAR* argv[]
	)
{
	std::vector<BYTE> binaryFileBytes;
	std::ifstream binaryFile;
	ULONG xorKey;
	std::string xorKeyHex;
	ULONG i;
	BYTE currentByte;
	std::string header;
	std::ofstream headerFile;

	if (argc < 3)
	{
		std::cout << "Usage: spectre-stager-util [driver file] [output header file]" << std::endl;
		return 0;
	}

	//
	// Read in the bytes of the binary file.
	//
	binaryFile.open(argv[1], std::ios_base::binary);
	binaryFileBytes = std::vector<BYTE>((std::istreambuf_iterator<char>(binaryFile)), (std::istreambuf_iterator<char>()));
	binaryFile.close();

	//
	// Set the seed to the current time so we don't
	// get the same random numbers every time.
	//
	srand(time(NULL));
    
	xorKey = rand() % 0xFF;

	//
	// Open the header file.
	//
	headerFile.open(argv[2]);	

	//
	// Add the prefix.
	//
	headerFile << "#pragma once\n\n#define SPECTRE_XOR_KEY " << xorKey << "\n\nunsigned char spectre_driver[" << binaryFileBytes.size() << "] = {";

	for (i = 0; i < binaryFileBytes.size(); i++)
	{
		//
		// Every 12th byte add a newline.
		//
		if (i % 11 == 0)
		{
			headerFile << std::endl << "\t";
		}

		//
		// Grab the current bytes so we can XOR them.
		//
		currentByte = binaryFileBytes[i];

		//
		// XOR the bytes.
		//
		currentByte ^= xorKey;

		//
		// Put the bytes into the header.
		//
		headerFile << "0x" << std::hex << std::uppercase << std::setfill('0') << std::setw(2) << SCAST<ULONG>(currentByte);

		//
		// If not the last byte, add a comma.
		//
		if (i != binaryFileBytes.size() - 1)
		{
			headerFile << ", ";
		}
	}

	//
	// Append the suffix.
	//
	headerFile << "\n};\n";

	headerFile.close();

	return 0;
}