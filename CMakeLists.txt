cmake_minimum_required((VERSION 3.10.2)
project(frida_stealth_bypass)

set(CMAKE_SYSTEM_NAME Android)
set(CMAKE_ANDROID_API 21)
set(CMAKE_ANDROID_ARCH_ABI arm64-v8a)
set(CMAKE_ANDROID_STL_TYPE c++_shared)

set(CMAKE_TOOLCHAIN_FILE $ENV{ANDROID_NDK}/build/cmake/android.toolchain.cmake)

add_library(bytehook STATIC IMPORTED)
set_target_properties(bytehook PROPERTIES IMPORTED_LOCATION ${CMAKE_CURRENT_SOURCE_DIR}/libbytehook.a)

add_library(stealth_fix SHARED stealth_fix.cpp)
target_link_libraries(stealth_fix bytehook log dl)
