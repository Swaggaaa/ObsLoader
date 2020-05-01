#include "Loader.h"
#include <iostream>
#include <memory>
#include "../KernelClientLib/KernelModule.h"
#include <Tlhelp32.h>
#include <stdexcept>

loader::loader(const std::string& dll_file_name)
{
    char dll_absolute_path[MAX_PATH];
    GetFullPathNameA(dll_file_name.c_str(), MAX_PATH, dll_absolute_path, nullptr);

    this->dll_path_ = std::string(dll_absolute_path);
}
 
void loader::inject_to_process(const std::string& target_process_name) const
{
    const int pid = get_process_pid(target_process_name);
    inject_dll(pid);
}

int loader::get_process_pid(const std::string& target_process_name)
{
    const HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(entry);

    if (!Process32First(snapshot, &entry))
    {
        throw std::runtime_error("Failed to create snapshot");
    }

    do
    {
        if (entry.szExeFile == target_process_name)
        {
            CloseHandle(snapshot);
            return entry.th32ProcessID;
        }
    } while (Process32Next(snapshot, &entry));

    throw std::runtime_error("Couldn't find process with name: " + target_process_name);
}

HANDLE loader::get_process_handle(const int pid)
{
    const HANDLE handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!handle)
    {
        throw std::runtime_error("Couldn't open handle to process");
    }
    return handle;
}