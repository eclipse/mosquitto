option(WITH_STATIC_LIBRARIES "Build static versions of the libmosquitto/pp libraries?" OFF)
option(WITH_PIC "Build the static library with PIC (Position Independent Code) enabled archives?" OFF)
add_subdirectory(cpp)

include_directories(${mosquitto_SOURCE_DIR} ${mosquitto_SOURCE_DIR}/lib
			${mosquitto_SOURCE_DIR}/src/deps
			${STDBOOL_H_PATH} ${STDINT_H_PATH}
			${OPENSSL_INCLUDE_DIR} ${PTHREAD_INCLUDE_DIR})
link_directories(${mosquitto_SOURCE_DIR}/lib)

set(C_SRC
	actions.c
	callbacks.c
	connect.c
	handle_auth.c
	handle_connack.c
	handle_disconnect.c
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
	mqtt_protocol.h
	net_mosq_ocsp.c net_mosq.c net_mosq.h
	options.c
	packet_datatypes.c
	packet_mosq.c packet_mosq.h
	property_mosq.c property_mosq.h
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
	util_mosq.c util_topic.c util_mosq.h
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

if (WITH_SRV)
	# Simple detect c-ares
	find_path(ARES_HEADER ares.h)
	if (ARES_HEADER)
		add_definitions("-DWITH_SRV")
		set (LIBRARIES ${LIBRARIES} cares)
	else (ARES_HEADER)
		message(WARNING "c-ares library not found.")
	endif (ARES_HEADER)
endif (WITH_SRV)

add_library(libmosquitto SHARED ${C_SRC})
set_target_properties(libmosquitto PROPERTIES
	POSITION_INDEPENDENT_CODE 1
	OUTPUT_NAME mosquitto
	PUBLIC_HEADER ${CMAKE_CURRENT_SOURCE_DIR}/mosquitto.h
	VERSION ${PROJECT_VERSION}
	SOVERSION 1
)

target_include_directories(
	libmosquitto
	INTERFACE
	$<BUILD_INTERFACE:${MOSQUITTO_INCLUDE_BUILD_DIR}>
	$<INSTALL_INTERFACE:include>
)

target_link_libraries(libmosquitto ${LIBRARIES})
install(TARGETS libmosquitto EXPORT ${MOSQUITTO_TARGETS_EXPORT_NAME} LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}" PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

if (WITH_STATIC_LIBRARIES)
	add_library(libmosquitto_static STATIC ${C_SRC})
	if (WITH_PIC)
		set_target_properties(libmosquitto_static PROPERTIES
			POSITION_INDEPENDENT_CODE 1
		)
	endif (WITH_PIC)

	target_link_libraries(libmosquitto_static ${LIBRARIES})

	set_target_properties(libmosquitto_static PROPERTIES
		PUBLIC_HEADER ${CMAKE_CURRENT_SOURCE_DIR}/mosquitto.h
		OUTPUT_NAME mosquitto
		VERSION ${PROJECT_VERSION}
	)

	target_include_directories(
		libmosquitto_static
		INTERFACE
		$<BUILD_INTERFACE:${MOSQUITTO_INCLUDE_BUILD_DIR}>
		$<INSTALL_INTERFACE:include>
	)

	target_compile_definitions(libmosquitto_static PUBLIC "LIBMOSQUITTO_STATIC")

	install(TARGETS libmosquitto_static EXPORT ${MOSQUITTO_TARGETS_EXPORT_NAME} ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}" PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
endif (WITH_STATIC_LIBRARIES)
