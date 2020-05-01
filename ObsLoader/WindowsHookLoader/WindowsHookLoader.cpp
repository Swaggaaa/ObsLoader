#include "WindowsHookLoader.h"
#include <iostream>
#include <stdexcept>
#include <Tlhelp32.h>
#include <vector>

typedef HHOOK(*fnPlayGame)(DWORD thread_id);

void windows_hook_loader::inject_dll(const int pid) const
{
    const auto thread_ids = get_thread_ids(pid);
    const auto exported_func_name = "PlayGame";
    const auto dll_handle = LoadLibraryA(this->dll_path_.c_str());
    const auto PlayGame = fnPlayGame(GetProcAddress(dll_handle, exported_func_name));
    auto hooks = std::vector<HHOOK>();

    for (auto thread_id : thread_ids)
    {
        const auto hook = PlayGame(thread_id);
        if (hook)
        {
            hooks.push_back(hook);
            std::cout << "[ SUCCESS ] SetWindowsHookExW for thread id: [" << thread_id << "] and hookId: [" << WH_GETMESSAGE << "]" << std::endl;
        }
        else
        {
            std::cerr << "[ FAIL ] SetWindowsHookExW for thread id: [" << thread_id << "] and hookId: [" << WH_GETMESSAGE << "]" << std::endl;
        }
    }
    std::cout << "Placed: [" << hooks.size() << "] hooks" << std::endl;

    while (true)
    {
        Sleep(1000);
    }
}

std::vector<DWORD> windows_hook_loader::get_thread_ids(const int process_pid)
{
    auto thread_pids = std::vector<DWORD>();
    const HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    THREADENTRY32 entry;
    entry.dwSize = sizeof(entry);

    if (!Thread32First(snapshot, &entry))
    {
        throw std::runtime_error("Failed to create snapshot");
    }

    do
    {
        if (entry.th32OwnerProcessID == process_pid)
        {
            thread_pids.push_back(entry.th32ThreadID);
        }
    } while (Thread32Next(snapshot, &entry));

    CloseHandle(snapshot);

    if (thread_pids.empty()) {
        throw std::runtime_error("Couldn't find any threads for process with pid: " + std::to_string(process_pid));
    }

    return thread_pids;
}
