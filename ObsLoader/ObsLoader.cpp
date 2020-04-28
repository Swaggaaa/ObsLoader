#include "ObsLoader.h"
#include <Windows.h>
#include <iostream>
#include <stdexcept>
#include "Loader/Loader.h"
#include "KernelClientLib/KernelModule.h"

int main(int argc, char** argv)
{
    if (argc != 3)
    {
        std::cout << "Usage: ./loader process_name dll_name" << std::endl;
        return 1;
    }

    std::cout << "Press enter to begin the injection" << std::endl;
    std::cin.get();

    try
    {
        KernelModule::init();
        while (!KernelModule::Ping())
        {
            std::cout << "Driver not answering" << std::endl;
            Sleep(1000);
        }

        std::cout << "Driver answered! It's     A L I V E " << std::endl;

        const auto target_process_name = std::string(argv[1]);
        const loader obs_loader{ std::string(argv[2]) };
        obs_loader.inject_to_process(target_process_name);
    }
    catch (std::runtime_error& ex)
    {
        std::cerr << "An exception happened during the execution: " << ex.what() << std::endl;
    }

    return 0;
}
