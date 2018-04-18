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

	option(WITH_THREADING "Include client library threading support?" ON)
	if (${WITH_THREADING} STREQUAL ON)
		target_compile_definitions(${LIB} PRIVATE WITH_THREADING)
		find_library(pthread REQUIRED)
		target_link_libraries(${LIB} PRIVATE pthread)
	endif (${WITH_THREADING} STREQUAL ON)

	if (${WITH_TLS} STREQUAL ON)
		find_package(OpenSSL REQUIRED)

		target_compile_definitions(${LIB} PRIVATE WITH_TLS)

		if (${WITH_TLS_PSK} STREQUAL ON)
			target_compile_definitions(${LIB} PRIVATE WITH_TLS_PSK)
		endif (${WITH_TLS_PSK} STREQUAL ON)

		if (${WITH_EC} STREQUAL ON)
			target_compile_definitions(${LIB} PRIVATE WITH_EC)
		endif (${WITH_EC} STREQUAL ON)

		target_link_libraries(${LIB} PRIVATE OpenSSL::SSL OpenSSL::Crypto)
	endif (${WITH_TLS} STREQUAL ON)

	if (${WITH_SOCKS} STREQUAL ON)
		target_compile_definitions(${LIB} PRIVATE WITH_SOCKS)
	endif (${WITH_SOCKS} STREQUAL ON)

	if (UNIX AND NOT APPLE)
		find_library(LIBRT rt)
		if (LIBRT)
			set (LIBRARIES ${LIBRARIES} rt)
		endif (LIBRT)
	endif (UNIX AND NOT APPLE)

	if (WIN32)
		target_link_libraries(${LIB} PRIVATE wsock32 ws2_32)
	endif (WIN32)

	if (${WITH_SRV} STREQUAL ON)
		# Simple detect c-ares
		find_path(ARES_HEADER ares.h)
		if (ARES_HEADER)
			target_compile_definitions(${LIB} PRIVATE WITH_SRV)
			target_link_libraries(${LIB} PRIVATE cares)
		else (ARES_HEADER)
			message(FATAL_ERROR "c-ares library not found.")
		endif (ARES_HEADER)
	endif (${WITH_SRV} STREQUAL ON)
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
