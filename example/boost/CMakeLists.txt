set(Boost_USE_STATIC_LIBS OFF)
set(Boost_USE_MULTITHREADED ON)
find_package(Boost 1.69.0 REQUIRED COMPONENTS system thread)
include_directories(${Boost_INCLUDE_DIRS})

add_executable(boost_spsc_queue spsc_queue.cpp)
set_property(TARGET boost_spsc_queue PROPERTY OUTPUT_NAME spsc_queue)
target_link_libraries(boost_spsc_queue PRIVATE ${Boost_LIBRARIES})

add_executable(boost_mpmc_queue mpmc_queue.cpp)
set_property(TARGET boost_mpmc_queue PROPERTY OUTPUT_NAME mpmc_queue)
target_link_libraries(boost_mpmc_queue PRIVATE ${Boost_LIBRARIES})

add_executable(boost_mpmc_stack mpmc_stack.cpp)
set_property(TARGET boost_mpmc_stack PROPERTY OUTPUT_NAME mpmc_stack)
target_link_libraries(boost_mpmc_stack PRIVATE ${Boost_LIBRARIES})
