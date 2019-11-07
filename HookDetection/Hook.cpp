#include <windows.h>
#include "..\mhook\mhook-lib\mhook.h"
#include "Hook.h"

typedef BOOL(WINAPI* PVirtualProtect)(
	_In_ LPVOID lpAddress,
	_In_ SIZE_T dwSize,
	_In_ DWORD flNewProtect,
	_Out_ PDWORD lpflOldProtect
	);

typedef BOOL(WINAPI* PVirtualProtectEx)(
	_In_ HANDLE hProcess,
	_In_ LPVOID lpAddress,
	_In_ SIZE_T dwSize,
	_In_ DWORD flNewProtect,
	_Out_ PDWORD lpflOldProtect
	);

PVirtualProtect OriginalVirtualProtectAddress = reinterpret_cast<PVirtualProtect>(::GetProcAddress(GetModuleHandle(TEXT("kernel32.dll")), "VirtualProtect"));
PVirtualProtectEx OriginalVirtualProtectExAddress = reinterpret_cast<PVirtualProtectEx>(::GetProcAddress(GetModuleHandle(TEXT("kernel32.dll")), "VirtualProtectEx"));
bool HooksWereInstalled = false;

void PrintHookerAddress(void* addressFromTryToHook)
{
	wchar_t msg[50] = { 0 };
	wsprintf(msg, L"Hook from address: %p", addressFromTryToHook);
	MessageBox(NULL, msg, L"HookDetected", 0);
}

bool ProcessHook(VOID* vpAddr, VOID* callerAddress)
{
	HMODULE hmodule;
	BOOL success = GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, reinterpret_cast<LPCTSTR>(vpAddr), &hmodule);
	if (success && HooksWereInstalled)
	{
		PrintHookerAddress(callerAddress);
		return true;
	}
	return false;
}

BOOL WINAPI HookedVirtualProtect(_In_ LPVOID lpAddress, _In_ SIZE_T dwSize, _In_ DWORD flNewProtect, _Out_ PDWORD lpflOldProtect)
{
	VOID* callerAddress;
	CaptureStackBackTrace(1, 1, &callerAddress, NULL);
	return ProcessHook(lpAddress, callerAddress)
		? false
		: OriginalVirtualProtectAddress(lpAddress, dwSize, flNewProtect, lpflOldProtect);
}

BOOL WINAPI HookedVirtualProtectEx(_In_ HANDLE hProcess, _In_ LPVOID lpAddress, _In_ SIZE_T dwSize, _In_ DWORD flNewProtect, _Out_ PDWORD lpflOldProtect)
{
	VOID* callerAddress;
	CaptureStackBackTrace(1, 1, &callerAddress, NULL);
	return ProcessHook(lpAddress, callerAddress)
		? false
		: OriginalVirtualProtectExAddress(hProcess, lpAddress, dwSize, flNewProtect, lpflOldProtect);
}

bool SetHooks()
{
	return Mhook_SetHook(reinterpret_cast<PVOID*>(&OriginalVirtualProtectAddress), HookedVirtualProtect) &&
		Mhook_SetHook(reinterpret_cast<PVOID*>(&OriginalVirtualProtectExAddress), HookedVirtualProtectEx);
}

void UnHook()
{
	HooksWereInstalled = false;
	Mhook_Unhook(reinterpret_cast<PVOID*>(&OriginalVirtualProtectAddress));
	Mhook_Unhook(reinterpret_cast<PVOID*>(&OriginalVirtualProtectExAddress));
}

Hook::~Hook()
{
	UnHook();
}

bool Hook::Initialize()
{
	HooksWereInstalled = SetHooks();
	return HooksWereInstalled;
}