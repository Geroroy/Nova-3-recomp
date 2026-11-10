cmake_minimum_required(VERSION 3.16)
project(nova3_runtime C)

add_library(nova3_runtime STATIC
    src/core.c src/memory.c src/libc.c src/libc_string.c src/libc_stdio.c
    src/libc_posix.c src/libc_pthread.c src/libc_math.c)
target_include_directories(nova3_runtime PUBLIC include)
target_compile_options(nova3_runtime PRIVATE -O2 -Wall -Wno-unused-function)
target_compile_definitions(nova3_runtime PRIVATE _GNU_SOURCE)
find_package(Threads REQUIRED)
target_link_libraries(nova3_runtime PUBLIC Threads::Threads m)
if(ANDROID)
    target_link_libraries(nova3_runtime PUBLIC log dl)
endif()
