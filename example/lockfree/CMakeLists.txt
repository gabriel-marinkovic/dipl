include(FetchContent)

FetchContent_Declare(
    lockfree
    GIT_REPOSITORY https://github.com/DNedic/lockfree.git
    GIT_TAG        2.0.8
)

FetchContent_MakeAvailable(lockfree)

include_directories("${lockfree_SOURCE_DIR}/include")

add_executable(spsc_queue spsc_queue.cpp)
target_link_libraries(spsc_queue PRIVATE lockfree)
