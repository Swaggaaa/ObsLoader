#include <iostream>
#include <stdexcept>
#include "Loader/Loader.h"
#include "LoadLibraryLoader/LoadLibraryLoader.h"
#include "WindowsHookLoader/WindowsHookLoader.h"

enum INJECTION_METHODS { IM_LOAD_LIBRARY = 1, IM_SET_WINDOWS_HOOK = 2 };

void initialize_loaders(char** argv)
{
    const auto target_process_name = std::string(argv[1]);
    const auto dll_file_name = std::string(argv[2]);
    int chosen_option;

    std::cout << "Choose method of injection: " << std::endl;
    std::cout << "1# LoadLibrary (Requires AndreKernelModule)" << std::endl;
    std::cout << "2# SetWindowsHookEx" << std::endl;
    std::cout << "Write your selection: ";
    std::cin >> chosen_option;

    try
    {
        std::unique_ptr<loader> obs_loader;
        switch (chosen_option)
        {
        case IM_LOAD_LIBRARY:
        {
            obs_loader = std::make_unique<load_library_loader>(load_library_loader(dll_file_name));
            break;
        }

        case IM_SET_WINDOWS_HOOK:
        {
            obs_loader = std::make_unique<windows_hook_loader>(windows_hook_loader(dll_file_name));
            break;
        }

        default:
            throw std::runtime_error("Invalid menu option chosen, faggot");
        }

        obs_loader->inject_to_process(target_process_name);
    }
    catch (std::runtime_error& ex)
    {
        std::cerr << "An exception happened during the execution: " << ex.what() << std::endl;
    }

}

int main(int argc, char** argv)
{
    if (argc != 3)
    {
        std::cout << "Usage: ./loader process_name dll_name" << std::endl;
        return 1;
    }

    initialize_loaders(argv);
    
    return 0;
}
