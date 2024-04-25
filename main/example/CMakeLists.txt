add_executable(basic basic.cpp)
add_executable(double_checked_locking double_checked_locking.cpp)
add_executable(test test.cpp)

install(
	TARGETS
		basic
		double_checked_locking
		test
	DESTINATION
		"${CMAKE_INSTALL_PREFIX}/example")
