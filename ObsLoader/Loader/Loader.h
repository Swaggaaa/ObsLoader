#pragma once

#include <string>
#include <Windows.h>

class loader
{
private:
    std::string dll_path_;

    static int get_process_pid(const std::string& target_process_name);
    static HANDLE get_process_handle(const int pid);
    void inject_dll(const HANDLE handle) const;
    void inject_dll(const int pid) const;

public:
    explicit loader(const std::string& dll_file_name);

    void inject_to_process(const std::string& target_process_name) const;
};