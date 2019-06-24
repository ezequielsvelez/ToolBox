#include <Windows.h>

void print_mitigations(HANDLE hProc);
// Policy Setters
void set_strict_handle_check_policy();
void set_system_call_disable_policy();
void set_signature_policy();