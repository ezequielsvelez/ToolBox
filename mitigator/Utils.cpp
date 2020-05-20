#include "Utils.h"
#include <iostream>

// print error
void print_error(const char *desc, DWORD errcode) {
	LPTSTR errorText = NULL;

	FormatMessage(
		// use system message tables to retrieve error text
		FORMAT_MESSAGE_FROM_SYSTEM
		// allocate buffer on local heap for error text
		| FORMAT_MESSAGE_ALLOCATE_BUFFER
		// Important! will fail otherwise, since we're not 
		// (and CANNOT) pass insertion parameters
		| FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,    // unused with FORMAT_MESSAGE_FROM_SYSTEM
		errcode,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPTSTR)&errorText,  // output 
		0, // minimum size for output buffer
		NULL);   // arguments - see note 

	if (errorText != NULL) {
		if (desc == NULL) desc = "Error";
		if (errorText[lstrlen((LPCTSTR)errorText) - 1] == '\n') errorText[lstrlen((LPCTSTR)errorText) - 1] = '\0';
		if (errorText[lstrlen((LPCTSTR)errorText) - 1] == '\r') errorText[lstrlen((LPCTSTR)errorText) - 1] = '\0';
		fprintf(stderr, "%s: 0x%08X: %s\n", desc, errcode, errorText);
		// release memory allocated by FormatMessage()
		LocalFree(errorText);
	}
}
