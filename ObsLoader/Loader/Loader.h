#pragma once

#include <string>
#include <Windows.h>

class loader
{
protected:
    std::string dll_path_;

    static int get_process_pid(const std::string& target_process_name);
    static HANDLE get_process_handle(const int pid);
    virtual void inject_dll(const int pid) const = 0;

public:
    virtual ~loader() = default;
    explicit loader(const std::string& dll_file_name);

    virtual void inject_to_process(const std::string& target_process_name) const;
};