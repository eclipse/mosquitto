option(WITH_STATIC_LIBRARIES "Build static versions of the libmosquitto/pp libraries?" OFF)
option(WITH_PIC "Build the static library with PIC (Position Independent Code) enabled archives?" OFF)
add_subdirectory(cpp)

include_directories(${mosquitto_SOURCE_DIR} ${mosquitto_SOURCE_DIR}/lib
			${STDBOOL_H_PATH} ${STDINT_H_PATH}
			${OPENSSL_INCLUDE_DIR} ${PTHREAD_INCLUDE_DIR})
link_directories(${mosquitto_SOURCE_DIR}/lib)

set(C_SRC
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
	logging_mosq.c logging_mosq.h
	loop.c
	memory_mosq.c memory_mosq.h
	messages_mosq.c messages_mosq.h
	mosquitto.c mosquitto.h
	mosquitto_internal.h
	mqtt3_protocol.h
	net_mosq.c net_mosq.h
	options.c
	packet_mosq.c packet_mosq.h
	read_handle.c read_handle.h
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
	util_mosq.c util_mosq.h
	will_mosq.c will_mosq.h)

set (LIBRARIES ${OPENSSL_LIBRARIES} ${PTHREAD_LIBRARIES})

if (UNIX AND NOT APPLE)
	find_library(LIBRT rt)
	if (LIBRT)
		set (LIBRARIES ${LIBRARIES} rt)
	endif (LIBRT)
endif (UNIX AND NOT APPLE)

if (WIN32)
	set (LIBRARIES ${LIBRARIES} ws2_32)
endif (WIN32)

if (${WITH_SRV} STREQUAL ON)
	# Simple detect c-ares
	find_path(ARES_HEADER ares.h)
	if (ARES_HEADER)
		add_definitions("-DWITH_SRV")
		set (LIBRARIES ${LIBRARIES} cares)
	else (ARES_HEADER)
		message(WARNING "c-ares library not found.")
	endif (ARES_HEADER)
endif (${WITH_SRV} STREQUAL ON)

add_library(libmosquitto SHARED ${C_SRC})
set_target_properties(libmosquitto PROPERTIES
	POSITION_INDEPENDENT_CODE 1
)

target_link_libraries(libmosquitto ${LIBRARIES})

set_target_properties(libmosquitto PROPERTIES
	OUTPUT_NAME mosquitto
	VERSION ${VERSION}
	SOVERSION 1
)

install(TARGETS libmosquitto RUNTIME DESTINATION "${BINDIR}" LIBRARY DESTINATION "${LIBDIR}")

if (${WITH_STATIC_LIBRARIES} STREQUAL ON)
	add_library(libmosquitto_static STATIC ${C_SRC})
	if (${WITH_PIC} STREQUAL ON)
		set_target_properties(libmosquitto_static PROPERTIES
			POSITION_INDEPENDENT_CODE 1
		)
	endif (${WITH_PIC} STREQUAL ON)

	target_link_libraries(libmosquitto_static ${LIBRARIES})

	set_target_properties(libmosquitto_static PROPERTIES
		OUTPUT_NAME mosquitto
		VERSION ${VERSION}
	)

	target_compile_definitions(libmosquitto_static PUBLIC "LIBMOSQUITTO_STATIC")
	install(TARGETS libmosquitto_static RUNTIME DESTINATION "${BINDIR}" ARCHIVE DESTINATION "${LIBDIR}")
endif (${WITH_STATIC_LIBRARIES} STREQUAL ON)

install(FILES mosquitto.h DESTINATION "${INCLUDEDIR}")

if (UNIX AND NOT APPLE)
	install(CODE "EXEC_PROGRAM(/sbin/ldconfig)")
endif (UNIX AND NOT APPLE)

