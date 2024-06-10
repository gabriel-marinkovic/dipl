include(ExternalProject)

ExternalProject_Add(ck
    GIT_REPOSITORY https://github.com/concurrencykit/ck.git
    GIT_TAG master
    CONFIGURE_COMMAND <SOURCE_DIR>/configure --prefix=<INSTALL_DIR>
    BUILD_COMMAND make
    INSTALL_COMMAND make install
)

ExternalProject_Get_Property(ck INSTALL_DIR)
include_directories(${INSTALL_DIR}/include)

add_executable(ck_spsc_queue spsc_queue.cpp)
set_property(TARGET ck_spsc_queue PROPERTY OUTPUT_NAME spsc_queue)
target_compile_options(ck_spsc_queue PRIVATE -fpermissive)
add_dependencies(ck_spsc_queue ck)
target_link_libraries(ck_spsc_queue PRIVATE "${INSTALL_DIR}/lib/libck.a")
