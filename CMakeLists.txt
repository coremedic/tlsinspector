cmake_minimum_required(VERSION 3.27)
project(tlsinspector)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_EXE_LINKER_FLAGS "-static")
include_directories(include)

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_definitions(-DDEBUG)
endif()

add_executable(tlsinspector src/main.cpp
        include/structs.hpp)
