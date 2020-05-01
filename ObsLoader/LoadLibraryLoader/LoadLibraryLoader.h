#pragma once

#include "../Loader/Loader.h"

class load_library_loader final : public loader
{
    void inject_dll(int pid) const override;
public:
    using loader::loader;
    ~load_library_loader() override;
};