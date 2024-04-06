cmake_minimum_required(VERSION 3.24)
project(dipl LANGUAGES CXX)

function (build_external_project target prefix)
	cmake_parse_arguments(
        PARSED_ARGS
        ""
        "GIT_REPOSITORY;GIT_TAG"
        "CMAKE_ARGS"
        ${ARGN})

    set(trigger_build_dir ${CMAKE_BINARY_DIR}/force_${target})

    #mktemp dir in build tree
    file(MAKE_DIRECTORY ${trigger_build_dir} ${trigger_build_dir}/build)

    #generate false dependency project
    set(CMAKE_LIST_CONTENT "
        cmake_minimum_required(VERSION 3.24)
        project(Dummy)
        include(ExternalProject)
        ExternalProject_add(
        	${target}
            PREFIX ${prefix}/${target}
            GIT_REPOSITORY ${PARSED_ARGS_GIT_REPOSITORY}
            GIT_TAG ${PARSED_ARGS_GIT_TAG}
            CMAKE_ARGS ${PARSED_ARGS_CMAKE_ARGS}
            INSTALL_COMMAND \"\")
        add_custom_target(trigger_${target})
        add_dependencies(trigger_${target} ${target})
    ")

    file(WRITE ${trigger_build_dir}/CMakeLists.txt "${CMAKE_LIST_CONTENT}")

    execute_process(
    	COMMAND ${CMAKE_COMMAND} -G${CMAKE_GENERATOR} ..
    	WORKING_DIRECTORY ${trigger_build_dir}/build)
    execute_process(
    	COMMAND ${CMAKE_COMMAND} --build . -j
    	WORKING_DIRECTORY ${trigger_build_dir}/build)

    execute_process(
    	COMMAND ${CMAKE_COMMAND} --install .
    	WORKING_DIRECTORY ${trigger_build_dir}/build)
endfunction()

build_external_project(
	DynamoRIO
	DynamoRIO_prefix
	GIT_REPOSITORY https://github.com/DynamoRIO/dynamorio.git
	GIT_TAG release_10.0.0
	CMAKE_ARGS -DCMAKE_INSTALL_PREFIX="${CMAKE_BINARY_DIR}/dynamorio_install")

set(CMAKE_C_COMPILER clang)
set(CMAKE_CXX_COMPILER clang++)

set(CMAKE_PREFIX_PATH ${CMAKE_PREFIX_PATH} ${CMAKE_BINARY_DIR}/force_DynamoRIO/build/DynamoRIO_prefix/DynamoRIO/src/DynamoRIO-build/)
message(STATUS ${CMAKE_PREFIX_PATH})
find_package(DynamoRIO)
if (NOT DynamoRIO_FOUND)
  message(FATAL_ERROR "DynamoRIO package required to build")
endif()

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_subdirectory(src)
add_subdirectory(example)

