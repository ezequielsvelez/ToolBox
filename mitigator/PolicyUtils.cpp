#include <iostream>
#include "Utils.h"

// stringification
#define xstr(s) str(s)
#define str(s) #s

#define GET_MITIGATION(proc, p, b, s) \
    if (!GetProcessMitigationPolicy((proc), (p), (b), (s))) { \
        if (0) { print_error(str(p), GetLastError()); } \
		    } else

// print mitigation function hproc
void print_mitigations(HANDLE hProc) {

	PROCESS_MITIGATION_DEP_POLICY                       dep = { 0 };
	PROCESS_MITIGATION_ASLR_POLICY                      aslr = { 0 };
	PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY       strict_handle_check = { 0 };
	PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY       system_call_disable = { 0 };
	PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY   extension_point_disable = { 0 };
	PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY          sigRestriction = { 0 };

	GET_MITIGATION(hProc, ProcessDEPPolicy, &dep, sizeof(dep)) {
		printf("ProcessDEPPolicy\n");
		printf(" Enable                                     %u\n", dep.Enable);
		printf(" DisableAtlThunkEmulation                   %u\n", dep.DisableAtlThunkEmulation);
	}

	GET_MITIGATION(hProc, ProcessASLRPolicy, &aslr, sizeof(aslr)) {
		printf("ProcessASLRPolicy\n");
		printf(" EnableBottomUpRandomization                %u\n", aslr.EnableBottomUpRandomization);
		printf(" EnableForceRelocateImages                  %u\n", aslr.EnableForceRelocateImages);
		printf(" EnableHighEntropy                          %u\n", aslr.EnableHighEntropy);
		printf(" DisallowStrippedImages                     %u\n", aslr.DisallowStrippedImages);
	}

	GET_MITIGATION(hProc, ProcessStrictHandleCheckPolicy, &strict_handle_check, sizeof(strict_handle_check)) {
		printf("ProcessStrictHandleCheckPolicy\n");
		printf(" RaiseExceptionOnInvalidHandleReference     %u\n", strict_handle_check.RaiseExceptionOnInvalidHandleReference);
		printf(" HandleExceptionsPermanentlyEnabled         %u\n", strict_handle_check.HandleExceptionsPermanentlyEnabled);
	}

	GET_MITIGATION(hProc, ProcessSystemCallDisablePolicy, &system_call_disable, sizeof(system_call_disable)) {
		printf("ProcessSystemCallDisablePolicy\n");
		printf(" DisallowWin32kSystemCalls                  %u\n", system_call_disable.DisallowWin32kSystemCalls);
	}

	GET_MITIGATION(hProc, ProcessExtensionPointDisablePolicy, &extension_point_disable, sizeof(extension_point_disable)) {
		printf("ProcessExtensionPointDisablePolicy\n");
		printf(" DisableExtensionPoints                     %u\n", extension_point_disable.DisableExtensionPoints);
	}

	GET_MITIGATION(hProc, ProcessSignaturePolicy, &sigRestriction, sizeof(sigRestriction)) {
		printf("ProcessSignaturePolicy\n");
		printf(" SignaturePolicy                            %u\n", sigRestriction.MicrosoftSignedOnly);
	}
}

void set_strict_handle_check_policy(){
	PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY policy = { 0 };;
	policy.RaiseExceptionOnInvalidHandleReference = 1;
	policy.HandleExceptionsPermanentlyEnabled = 1;

	BOOL res = SetProcessMitigationPolicy(ProcessStrictHandleCheckPolicy, &policy, sizeof(policy));

	if (!res){
		DWORD err = GetLastError();
		print_error("Fail set mitigation", err);
	}
}

void set_system_call_disable_policy(){
	PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY policy = { 0 };;
	policy.DisallowWin32kSystemCalls = 1;

	BOOL res = SetProcessMitigationPolicy(ProcessSystemCallDisablePolicy, &policy, sizeof(policy));

	if (!res){
		DWORD err = GetLastError();
		print_error("Fail set mitigation", err);
	}
}

void set_signature_policy(){
	PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY policy = { 0 };;
	policy.MicrosoftSignedOnly = 1;

	BOOL res = SetProcessMitigationPolicy(ProcessSignaturePolicy, &policy, sizeof(policy));

	if (!res){
		DWORD err = GetLastError();
		print_error("Fail set mitigation", err);
	}
}
