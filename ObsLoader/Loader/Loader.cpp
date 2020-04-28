#include "Loader.h"
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

void loader::inject_dll(const HANDLE handle) const
{
    const std::string load_library_proc_name = "LoadLibraryA";
    const std::string load_library_dll = "kernel32.dll";
    const auto LoadLibraryA = LPVOID(GetProcAddress(GetModuleHandleA(load_library_dll.c_str()), load_library_proc_name.c_str()));
    const auto allocated_dll_name = VirtualAllocEx(handle, nullptr, load_library_proc_name.length(), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

    if (!WriteProcessMemory(handle, allocated_dll_name, this->dll_path_.c_str(), this->dll_path_.length(), nullptr))
    {
        throw std::runtime_error("Failed to write DLL path into the target process");
    }

    if (!CreateRemoteThread(handle, nullptr, 0, LPTHREAD_START_ROUTINE(LoadLibraryA), LPVOID(allocated_dll_name), 0, nullptr))
    {
        throw std::runtime_error("Failed to create a remote thread on target process");
    }

    CloseHandle(handle);
}

void loader::inject_dll(const int pid) const
{
    const std::string load_library_proc_name = "LoadLibraryA";
    const std::string load_library_dll = "kernel32.dll";
    const auto LoadLibraryA = LPVOID(GetProcAddress(GetModuleHandleA(load_library_dll.c_str()), load_library_proc_name.c_str()));
    const auto allocated_dll_name = KernelModule::VirtualAlloc(pid, nullptr, load_library_proc_name.length(), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

    //if (!KernelModule::WriteProcessMemory(pid, allocated_dll_name, PVOID(this->dll_path_.c_str()), this->dll_path_.length(), nullptr))
    if (!KernelModule::WriteProcessMemoryFromLoader(pid, allocated_dll_name, PVOID(this->dll_path_.c_str()), this->dll_path_.length()))
    {
        throw std::runtime_error("Failed to write DLL path into the target process");
    }

    if (!KernelModule::CreateThread(pid, 0, PTHREAD_START_ROUTINE(LoadLibraryA), LPVOID(allocated_dll_name), 0, nullptr))
    {
        throw std::runtime_error("Failed to create a remote thread on target process");
    }
}
