set(shared_src client_shared.c client_shared.h client_props.c)

add_library(client-common INTERFACE)
target_link_libraries(client-common INTERFACE common-options)
target_include_directories(client-common INTERFACE
	"${OPENSSL_INCLUDE_DIR}"
	"${mosquitto_SOURCE_DIR}"
)
target_sources(client-common INTERFACE ${shared_src})

if(WITH_SRV)
	target_compile_definitions(client-common INTERFACE "-DWITH_SRV")
endif()

if(WITH_WEBSOCKETS AND WITH_WEBSOCKETS_BUILTIN)
	target_compile_definitions(client-common INTERFACE "-DWITH_WEBSOCKETS=WS_IS_BUILTIN")
endif()

add_executable(mosquitto_pub pub_client.c pub_shared.c)
add_executable(mosquitto_sub sub_client.c sub_client_output.c)
add_executable(mosquitto_rr rr_client.c pub_shared.c sub_client_output.c)


if (WITH_THREADING AND NOT WIN32)
	set(THREADS_PREFER_PTHREAD_FLAG ON)
	find_package(Threads REQUIRED)

	target_link_libraries(client-common INTERFACE Threads::Threads)
endif()

if(WITH_BUNDLED_DEPS)
	target_include_directories(mosquitto_sub PRIVATE "${mosquitto_SOURCE_DIR}/deps")
	target_include_directories(mosquitto_rr PRIVATE "${mosquitto_SOURCE_DIR}/deps")
endif()

if(CJSON_FOUND)
	target_link_libraries(client-common INTERFACE cJSON)
endif()

if(WITH_STATIC_LIBRARIES)
	target_link_libraries(client-common INTERFACE libmosquitto_static)
else()
	target_link_libraries(client-common INTERFACE libmosquitto)
endif()

if(QNX)
	target_link_libraries(client-common INTERFACE socket)
endif()

target_link_libraries(mosquitto_pub PRIVATE client-common)
target_link_libraries(mosquitto_sub PRIVATE client-common)
target_link_libraries(mosquitto_rr PRIVATE client-common)

install(TARGETS mosquitto_pub RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}")
install(TARGETS mosquitto_sub RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}")
install(TARGETS mosquitto_rr RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}")
