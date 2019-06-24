#pragma once

#define _WIN32_WINNT 0x0602
#include <SDKDDKVer.h>

#include <iostream>
#include <stdlib.h>

#include <Windows.h>
#include <strsafe.h>
#include "Utils.h"
#include "PolicyUtils.h"

using namespace std;

void usage(const char *p) {
	cout << "usage: " << p << endl;
	cout << p << " -get <pid>    : returns the list of policies enabled for the process" << endl;
	cout << p << " -set <policies> : set the mitigation policy for this process" << endl;
	cout << "<policies> :" << endl;
	cout << "\t\t" << "s : Signature Policy" << endl;

	cout << "\t example: " << p << "-set sch" << endl;
}

void set_mitigations(string p){

	for (auto &f : p){
		switch (f)
		{
		case 's':
			set_signature_policy();
			break;
		case 'c':
			set_system_call_disable_policy();
			break;
		case 'h':
			set_strict_handle_check_policy();
			break;
		default:
			usage("util");
			break;
		}
	}
}

int main(int argc, char* argv[]) {
	HANDLE hProc = INVALID_HANDLE_VALUE;

	if (argc < 3) {
		usage(argv[0]);
		return EXIT_FAILURE;
	}
	// Print process pid
	DWORD cpid = GetCurrentProcessId();
	cout << cpid << endl;

	string command(argv[1]);
	if (command == "-set"){
		if (argv[2] == nullptr){
			usage(argv[0]);
			return EXIT_FAILURE;
		}

		string policies(argv[2]);
		set_mitigations(policies);
		// Check Policies
		hProc = GetCurrentProcess();
		print_mitigations(hProc);
		cout << "enter any character to exit" << endl;
		int input;
		std::cin >> input;
	}
	else if (command == "-get"){
		if (argv[2] == nullptr){
			usage(argv[0]);
			return EXIT_FAILURE;
		}

		DWORD pid = 0;
		pid = strtoul(argv[2], NULL, 0);
		if (pid == 0) {
			usage(argv[0]);
			return EXIT_FAILURE;
		}

		hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, (DWORD)pid);
		if (hProc == NULL) {
			print_error("OpenProcess", GetLastError());
			return EXIT_FAILURE;
		}

		print_mitigations(hProc);
	}else{
		usage(argv[0]);
		return EXIT_FAILURE;
	}

	CloseHandle(hProc);

	return EXIT_SUCCESS;
}