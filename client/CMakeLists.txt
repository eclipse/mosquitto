set(shared_src client_shared.c client_shared.h client_props.c)

add_library(client-common INTERFACE)
target_link_libraries(client-common INTERFACE common-options)
target_include_directories(client-common INTERFACE
	"${CJSON_INCLUDE_DIRS}"
	"${OPENSSL_INCLUDE_DIR}"
)

target_sources(client-common INTERFACE ${shared_src})

if(WITH_TLS)
	target_link_libraries(client-common INTERFACE OpenSSL::SSL)
endif()

if(WITH_SRV)
	target_compile_definitions(client-common INTERFACE "-DWITH_SRV")
endif()

if(WITH_WEBSOCKETS AND WITH_WEBSOCKETS_BUILTIN)
	target_compile_definitions(client-common INTERFACE "-DWITH_WEBSOCKETS=WS_IS_BUILTIN")
endif()

custom_add_executable(mosquitto_pub pub_client.c pub_shared.c)
custom_add_executable(mosquitto_sub sub_client.c sub_client_output.c)
custom_add_executable(mosquitto_rr rr_client.c pub_shared.c sub_client_output.c)


if (WITH_THREADING AND NOT WIN32)
	set(THREADS_PREFER_PTHREAD_FLAG ON)
	find_package(Threads REQUIRED)

	target_link_libraries(client-common INTERFACE Threads::Threads)
endif()

if(CJSON_FOUND)
	target_link_libraries(client-common INTERFACE cjson)
endif()

if(WITH_STATIC_LIBRARIES)
	target_link_libraries(client-common INTERFACE libmosquitto_static)
else()
	target_link_libraries(client-common INTERFACE libmosquitto)
endif()

if(QNX)
	target_link_libraries(client-common INTERFACE socket)
endif()

target_link_libraries(mosquitto_pub PRIVATE client-common libmosquitto_common)
target_link_libraries(mosquitto_sub PRIVATE client-common libmosquitto_common)
target_link_libraries(mosquitto_rr PRIVATE client-common libmosquitto_common)

custom_install(TARGETS mosquitto_pub RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}")
custom_install(TARGETS mosquitto_sub RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}")
custom_install(TARGETS mosquitto_rr RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}")
