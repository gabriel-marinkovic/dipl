add_library(test_tools SHARED test_tools.cpp)
target_include_directories(test_tools PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
