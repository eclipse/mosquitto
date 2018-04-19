add_subdirectory(cpp)

add_library(libmosquitto
	actions.c
	callbacks.c
	connect.c
	handle_connack.c
	handle_ping.c
	handle_pubackcomp.c
	handle_publish.c
	handle_pubrec.c
	handle_pubrel.c
	handle_suback.c
	handle_unsuback.c
	helpers.c
	logging_mosq.c
	loop.c
	memory_mosq.c
	messages_mosq.c
	mosquitto.c
	options.c
	packet_mosq.c
	read_handle.c
	send_connect.c
	send_disconnect.c
	send_mosq.c
	send_publish.c
	send_subscribe.c
	send_unsubscribe.c
	send_mosq.c send_mosq.h
	socks_mosq.c
	srv_mosq.c
	thread_mosq.c
	time_mosq.c
	tls_mosq.c
	utf8_mosq.c
	util_mosq.c
	will_mosq.c
)

add_library(libmosquitto_with_broker STATIC
	handle_ping.c
	handle_pubackcomp.c
	handle_pubrec.c
	handle_pubrel.c
	handle_suback.c
	handle_unsuback.c
	memory_mosq.c
	net_mosq.c
	packet_mosq.c
	send_mosq.c
	send_connect.c
	send_disconnect.c
	send_publish.c
	send_subscribe.c
	send_unsubscribe.c
	time_mosq.c
	tls_mosq.c
	util_mosq.c
	utf8_mosq.c
	will_mosq.c
)
target_compile_definitions(libmosquitto_with_broker PUBLIC WITH_BROKER)
target_include_directories(libmosquitto_with_broker PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/../src")

foreach(LIB libmosquitto libmosquitto_with_broker)
	target_include_directories(${LIB}
		PUBLIC
		"${CMAKE_CURRENT_SOURCE_DIR}"
		"${CMAKE_CURRENT_SOURCE_DIR}/../"
	)

	target_compile_definitions(${LIB}
		PUBLIC
		CMAKE
		VERSION="${VERSION}"
	)

	if (${WITH_THREADING} STREQUAL ON)
		find_package (Threads REQUIRED)
		target_compile_definitions(${LIB} PUBLIC WITH_THREADING)
		target_link_libraries(${LIB} PRIVATE Threads::Threads)
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
			target_link_libraries(${LIB} PRIVATE rt)
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
)
if (${WITH_STATIC_LIBRARIES} STREQUAL ON)
	set(BUILD_SHARED_LIBS ON)
	target_compile_definitions(libmosquitto PUBLIC LIBMOSQUITTO_STATIC)

	if (${WITH_PIC} STREQUAL ON)
		set_target_properties(libmosquitto PROPERTIES POSITION_INDEPENDENT_CODE 1)
	endif (${WITH_PIC} STREQUAL ON)
else (${WITH_STATIC_LIBRARIES} STREQUAL ON)
	set_target_properties(libmosquitto PROPERTIES SOVERSION 1)
endif (${WITH_STATIC_LIBRARIES} STREQUAL ON)

install(TARGETS libmosquitto
	RUNTIME DESTINATION "${BINDIR}"
	ARCHIVE DESTINATION "${LIBDIR}"
	LIBRARY DESTINATION "${LIBDIR}"
)
install(FILES mosquitto.h DESTINATION "${INCLUDEDIR}")

if (UNIX AND NOT APPLE)
	install(CODE "EXEC_PROGRAM(/sbin/ldconfig)")
endif (UNIX AND NOT APPLE)
