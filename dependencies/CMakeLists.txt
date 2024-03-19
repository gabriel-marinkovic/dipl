cmake_minimum_required(VERSION 3.24)
project(dependencies)

include(ExternalProject)

ExternalProject_add(
    DynamoRIO
    PREFIX DynamoRIO
    GIT_REPOSITORY https://github.com/DynamoRIO/dynamorio.git
    GIT_TAG release_10.0.0
    CMAKE_ARGS
        "-DCMAKE_INSTALL_PREFIX=${CMAKE_INSTALL_PREFIX}/DynamoRIO"
        "-DCMAKE_PREFIX_PATH=${CMAKE_PREFIX_PATH}/DynamoRIO")
