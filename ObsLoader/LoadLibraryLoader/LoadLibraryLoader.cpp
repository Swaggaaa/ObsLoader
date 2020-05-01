#include "LoadLibraryLoader.h"

#include <iostream>


#include "../KernelClientLib/KernelModule.h"

void load_library_loader::inject_dll(const int pid) const
{
    KernelModule::init();
    while (!KernelModule::Ping())
    {
        std::cout << "Driver not answering" << std::endl;
        Sleep(1000);
    }

    std::cout << "Driver answered! It's     A L I V E " << std::endl;

    const std::string load_library_proc_name = "LoadLibraryA";
    const std::string load_library_import = "kernel32.dll";
    const auto LoadLibraryA = LPVOID(GetProcAddress(GetModuleHandleA(load_library_import.c_str()), load_library_proc_name.c_str()));
    const auto allocated_dll_name = KernelModule::VirtualAlloc(pid, nullptr, load_library_proc_name.length(), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    const auto allocated_dll_name_content = std::make_unique<char[]>(50);
    const auto load_library_header = std::make_unique<char[]>(100);
    SIZE_T bytesRead = 0;
    LONG exit_code = 1337;

    if (!KernelModule::ReadProcessMemory(PVOID(pid), allocated_dll_name, allocated_dll_name_content.get(), load_library_proc_name.length(), &bytesRead))
    {
        throw std::runtime_error("Can't read allocated mem");
    }
    std::cout << "[BEFORE] Content was: " << allocated_dll_name_content << std::endl;

    if (!KernelModule::WriteProcessMemory(pid, allocated_dll_name, PVOID(this->dll_path_.c_str()), this->dll_path_.length(), nullptr))
    {
        throw std::runtime_error("Failed to write DLL path into the target process");
    }

    if (!KernelModule::ReadProcessMemory(PVOID(pid), allocated_dll_name, allocated_dll_name_content.get(), 50, &bytesRead))
    {
        throw std::runtime_error("Can't read written mem");
    }
    std::cout << "[AFTER] Content was: " << allocated_dll_name_content << std::endl;

    const auto LdrLoadDll = LPVOID(GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryW"));
    if (!LdrLoadDll)
    {
        throw std::runtime_error("LdrLoadDll couldn't be resolved");
    }

    if (!KernelModule::ReadProcessMemory(PVOID(pid), LdrLoadDll, load_library_header.get(), 100, &bytesRead))
    {
        throw std::runtime_error("Can't read LdrLoadDll contents inside target process");
    }
    std::cout << "LdrLoadDll sig is: ";
    for (int i = 0; i < 100; ++i)
        std::cout << std::hex << "0x" << int(0xFF & load_library_header[i]) << "\\";
    std::cout << std::endl;


    if (!KernelModule::CreateThread(pid, 0, PTHREAD_START_ROUTINE(LoadLibraryA), LPVOID(allocated_dll_name), 0, nullptr, &exit_code))
    {
        throw std::runtime_error("Failed to create a remote thread on target process");
    }
    std::cout << "Thread exited with code: " << exit_code << std::endl;
}

load_library_loader::~load_library_loader()
{
}
