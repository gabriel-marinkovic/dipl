cmake_minimum_required(VERSION 3.24)

if (NOT CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
    set (
        CMAKE_INSTALL_PREFIX "${CMAKE_CURRENT_SOURCE_DIR}/install"
        CACHE PATH "default_install_path" FORCE)
endif()
if (NOT DEFINED CMAKE_PREFIX_PATH)
    set(CMAKE_PREFIX_PATH "${CMAKE_INSTALL_PREFIX}")
endif()

project(superbuild)

include(ExternalProject)

add_subdirectory(dependencies)

ExternalProject_Add(main
    PREFIX main
    URL ${CMAKE_CURRENT_SOURCE_DIR}/main
    CMAKE_ARGS
        "-DCMAKE_INSTALL_PREFIX=${CMAKE_INSTALL_PREFIX}"
        "-DCMAKE_PREFIX_PATH=${CMAKE_PREFIX_PATH}"
    DEPENDS DynamoRIO
)
