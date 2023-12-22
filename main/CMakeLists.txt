cmake_minimum_required(VERSION 3.28)

project(app)
set(CXX_STANDARD 23)

file(GLOB APP_SOURCES "*.cpp" "*.hpp")

add_executable(app ${APP_SOURCES})
target_link_libraries(app PRIVATE mnetstat)

add_custom_command(TARGET app POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        $<TARGET_FILE:mnetstat>
        $<TARGET_FILE_DIR:app>
)

