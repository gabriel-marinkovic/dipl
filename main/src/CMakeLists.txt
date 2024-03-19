add_library(client SHARED client.cpp common.cpp)
configure_DynamoRIO_client(client)
use_DynamoRIO_extension(client drmgr)
use_DynamoRIO_extension(client drreg)
use_DynamoRIO_extension(client drutil)
use_DynamoRIO_extension(client drx)

install(
	TARGETS
		client
	DESTINATION
		"${CMAKE_INSTALL_PREFIX}/client")
