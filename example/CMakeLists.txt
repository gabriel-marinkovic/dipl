add_compile_options(-g -ggdb -pthread -O2)

link_libraries(test_tools)
include_directories("../src/test_tools")

add_subdirectory(lockfree)

add_executable(basic basic.cpp)
add_executable(double_checked_locking double_checked_locking.cpp)
add_executable(mutex mutex.cpp)
add_executable(fairlock fairlock.cpp)
add_executable(stack_naive stack_naive.cpp)
add_executable(stack_lockfree stack_lockfree.cpp)
add_executable(test test.cpp)
