#pragma once
#include <vector>

#include "../Loader/Loader.h"

class windows_hook_loader final: public loader
{
protected:
    void inject_dll(const int pid) const override;
    static std::vector<DWORD> get_thread_ids(int process_pid);
public:
    using loader::loader;
    ~windows_hook_loader() override = default;
};
