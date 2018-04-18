add_library(libmosquitto SHARED
	logging_mosq.c
	memory_mosq.c
	messages_mosq.c
	mosquitto.c
	net_mosq.c
	read_handle.c
	read_handle_client.c
	read_handle_shared.c
	send_client_mosq.c
	send_mosq.c
	socks_mosq.c
	srv_mosq.c
	thread_mosq.c
	time_mosq.c
	tls_mosq.c
	util_mosq.c
	will_mosq.c
)
add_library(libmosquitto_with_broker SHARED
	memory_mosq.c
	net_mosq.c
	read_handle_shared.c
	send_client_mosq.c
	send_mosq.c
	time_mosq.c
	tls_mosq.c
	util_mosq.c
	will_mosq.c
)
target_compile_definitions(libmosquitto_with_broker PUBLIC WITH_BROKER)
target_include_directories(libmosquitto_with_broker PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/../src")

add_subdirectory(cpp)

foreach(LIB libmosquitto libmosquitto_with_broker)
	target_include_directories(${LIB}
		PUBLIC
		"${CMAKE_CURRENT_SOURCE_DIR}"
		"${CMAKE_CURRENT_SOURCE_DIR}/../"
	)

	target_compile_definitions(${LIB}
		PUBLIC
		CMAKE
		VERSION=\"1.4.15\"
		TIMESTAMP=\"${TIMESTAMP}\"
	)

	if (UNIX AND NOT APPLE)
		find_library(LIBRT rt)
		if (LIBRT)
			target_link_libraries(${LIB} PUBLIC rt)
		endif (LIBRT)
	endif (UNIX AND NOT APPLE)

	if (WIN32)
		target_link_libraries(${LIB} PUBLIC wsock32 ws2_32)
	endif (WIN32)

	# ========================================
	# Common and client only options
	# ========================================
	if (${WITH_TLS} STREQUAL ON)
		find_package(OpenSSL REQUIRED)

		target_compile_definitions(${LIB} PUBLIC WITH_TLS)

		if (${WITH_TLS_PSK} STREQUAL ON)
			target_compile_definitions(${LIB} PUBLIC WITH_TLS_PSK)
		endif (${WITH_TLS_PSK} STREQUAL ON)

		if (${WITH_EC} STREQUAL ON)
			target_compile_definitions(${LIB} PUBLIC WITH_EC)
		endif (${WITH_EC} STREQUAL ON)

		target_link_libraries(${LIB} PUBLIC OpenSSL::SSL OpenSSL::Crypto)
	endif (${WITH_TLS} STREQUAL ON)

	if (${WITH_THREADING} STREQUAL ON)
		target_compile_definitions(${LIB} PUBLIC WITH_THREADING)
		find_library(pthread REQUIRED)
		target_link_libraries(${LIB} PUBLIC pthread)
	endif (${WITH_THREADING} STREQUAL ON)

	if (${WITH_SRV} STREQUAL ON)
		# Simple detect c-ares
		find_path(ARES_HEADER ares.h)
		if (ARES_HEADER)
			target_compile_definitions(${LIB} PUBLIC WITH_SRV)
			target_link_libraries(${LIB} PUBLIC cares)
		else (ARES_HEADER)
			message(FATAL_ERROR "c-ares library not found.")
		endif (ARES_HEADER)
	endif (${WITH_SRV} STREQUAL ON)

	if (${WITH_SOCKS} STREQUAL ON)
		target_compile_definitions(${LIB} PUBLIC WITH_SOCKS)
	endif (${WITH_SOCKS} STREQUAL ON)
endforeach(LIB)

# ========================================
# Installation
# ========================================
# install only libmosquitto
set_target_properties(libmosquitto PROPERTIES
	OUTPUT_NAME mosquitto
	VERSION ${VERSION}
	SOVERSION 1
)
install(TARGETS libmosquitto RUNTIME DESTINATION "${BINDIR}" LIBRARY DESTINATION "${LIBDIR}")
install(FILES mosquitto.h DESTINATION "${INCLUDEDIR}")

if (UNIX)
	install(CODE "EXEC_PROGRAM(/sbin/ldconfig)")
endif (UNIX)

# ========================================
# Broker only options
# ========================================
if (${WITH_ADNS} STREQUAL ON)
	target_compile_definitions(libmosquitto_with_broker PUBLIC WITH_ADNS)
	target_link_libraries(libmosquitto_with_broker PUBLIC anl)
endif (${WITH_ADNS} STREQUAL ON)

if (${WITH_WRAP} STREQUAL ON)
	target_compile_definitions(libmosquitto_with_broker PUBLIC WITH_WRAP)
	target_link_libraries(libmosquitto_with_broker PUBLIC wrap)
endif (${WITH_WRAP} STREQUAL ON)

if (${WITH_BRIDGE} STREQUAL ON)
	target_compile_definitions(libmosquitto_with_broker PUBLIC WITH_BRIDGE)
endif (${WITH_BRIDGE} STREQUAL ON)

if (${WITH_PERSISTENCE} STREQUAL ON)
	target_compile_definitions(libmosquitto_with_broker PUBLIC WITH_PERSISTENCE)
endif (${WITH_PERSISTENCE} STREQUAL ON)

if (${WITH_MEMORY_TRACKING} STREQUAL ON)
	target_compile_definitions(libmosquitto_with_broker PUBLIC WITH_MEMORY_TRACKING)
endif (${WITH_MEMORY_TRACKING} STREQUAL ON)

if (${WITH_SYS_TREE} STREQUAL ON)
	target_compile_definitions(libmosquitto_with_broker PUBLIC WITH_SYS_TREE)
endif (${WITH_SYS_TREE} STREQUAL ON)

if (${WITH_WEBSOCKETS} STREQUAL ON)
	find_package(Libwebsockets REQUIRED)
	target_compile_definitions(libmosquitto_with_broker PUBLIC WITH_WEBSOCKETS)
	target_link_libraries(libmosquitto_with_broker PUBLIC websockets)
endif (${WITH_WEBSOCKETS} STREQUAL ON)

if (${WITH_TLS} STREQUAL ON)
	if (${WITH_EC} STREQUAL ON)
		target_compile_definitions(libmosquitto_with_broker PUBLIC WITH_EC)
	endif (${WITH_EC} STREQUAL ON)
endif (${WITH_TLS} STREQUAL ON)

if(NOT APPLE)
	if (${WITH_UUID} STREQUAL ON)
		target_compile_definitions(libmosquitto_with_broker PUBLIC WITH_UUID)
		target_link_libraries(libmosquitto_with_broker PUBLIC uuid)
	endif (${WITH_UUID} STREQUAL ON)
endif(NOT APPLE)
