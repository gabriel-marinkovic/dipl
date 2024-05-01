add_compile_options(-g -ggdb -pthread -O2)

add_executable(basic basic.cpp)
add_executable(double_checked_locking double_checked_locking.cpp)
add_executable(mutex mutex.cpp)
add_executable(test test.cpp)
