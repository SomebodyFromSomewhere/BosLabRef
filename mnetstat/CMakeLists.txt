cmake_minimum_required(VERSION 3.28)

project(mnetstat)
set(CXX_STANDARD 23)

file(GLOB MNETSTAT_SOURCES "*.cpp" "*.hpp")

add_library(mnetstat SHARED ${MNETSTAT_SOURCES})
target_compile_definitions(mnetstat PRIVATE MNETSTAT_EXPORT_DLL)

target_include_directories(mnetstat PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})