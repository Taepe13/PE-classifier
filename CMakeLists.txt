cmake_minimum_required(VERSION 3.15)

project(pe-classifier LANGUAGES CXX)

# C++17
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(MSVC)
    add_compile_options(/W4 /permissive-)
else()
    add_compile_options(-Wall -Wextra -Wpedantic)
endif()

add_executable(pe-classifier
               src/main.cpp
               src/PeFile.cpp
               src/PeParser.cpp
               src/Features.cpp)

target_include_directories(pe-classifier PRIVATE include)

if(WIN32)
    target_link_libraries(pe-classifier PRIVATE)
endif()