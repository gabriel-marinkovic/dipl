cmake_minimum_required(VERSION 3.15)
project(dipl LANGUAGES CXX)

option(BUILD_DYNAMORIO "Build DynamoRIO" OFF)

include(FetchContent)

if(BUILD_DYNAMORIO)
    FetchContent_Declare(
      dynamorio
      GIT_REPOSITORY https://github.com/DynamoRIO/dynamorio.git
      GIT_TAG release_10.0.0
    )
    FetchContent_MakeAvailable(dynamorio)
else()
    set(CMAKE_CXX_STANDARD 23)
	set(CMAKE_CXX_STANDARD_REQUIRED ON)
	set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -g3 -ggdb")

	message(DynamoRIO_DIR="${DynamoRIO_DIR}")

	find_package(DynamoRIO)
	if (NOT DynamoRIO_FOUND)
	  message(FATAL_ERROR "DynamoRIO package required to build")
	endif()

	add_subdirectory(src)
	add_subdirectory(example)
endif()
