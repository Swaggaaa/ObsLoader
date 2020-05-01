#pragma once
#include <Windows.h>

namespace KernelModule
{
	void init();

	BOOL ReadProcessMemory(PVOID pid, PVOID address, PVOID destination, SIZE_T size, SIZE_T* bytesRead);
	template <class T>
	BOOL ReadProcessMemory(PVOID pid, PVOID address, T* destination) {
		return ReadProcessMemory(pid, address, destination, sizeof(T), nullptr);
	}



	template <class T>
	T Read(PVOID pid, PVOID address) {
		T value;
		ReadProcessMemory(pid, address, &value, sizeof(T), nullptr);
		return value;
	}

	template <class T>
	T Read(PVOID pid, DWORD64 address) {
		return Read<T>(pid, PVOID(address));
	}

	BOOL WriteProcessMemory(UINT64 pid, PVOID address, PVOID source, SIZE_T size, SIZE_T* bytesWritten);
	template <class T>
	BOOL WriteProcessMemory(UINT64 pid, PVOID address, T* source) {
		return WriteProcessMemory(pid, address, PVOID(source), sizeof(T), nullptr);
	}


	BOOL WriteProcessMemoryFromLoader(UINT64 pid, PVOID address, PVOID source, SIZE_T size);

	PVOID GetModuleAddress(UINT64 pid, LPCWSTR moduleName);

	LPVOID VirtualAlloc(UINT64 UniqueProcessPid, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);

	BOOL CreateThread
	(
		UINT64 UniqueProcessPid,
		SIZE_T dwStackSize,
		LPVOID lpStartAddress,
		LPVOID lpParameter,
		DWORD  dwCreationFlags,
		LPDWORD lpThreadId,
		LONG* exitStatus
	);

	BOOL Ping();

}