# CMakeList.txt : CMake project for ObsLoader, include source and define
# project specific logic here.
#
cmake_minimum_required (VERSION 3.8)

# Add source to this project's executable.
add_executable (ObsLoader "ObsLoader.cpp" "ObsLoader.h" "loader/loader.cpp" "KernelClientLib/KernelModule.h" "KernelClientLib/KernelModule.cpp")

# TODO: Add tests and install targets if needed.
