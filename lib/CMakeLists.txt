option(WITH_LIB_CPP "Build C++ library?" ON)
if (WITH_LIB_CPP)
	add_subdirectory(cpp)
endif (WITH_LIB_CPP)

include_directories(${mosquitto_SOURCE_DIR} ${mosquitto_SOURCE_DIR}/lib
			${mosquitto_SOURCE_DIR}/include
			${STDBOOL_H_PATH} ${STDINT_H_PATH}
			${OPENSSL_INCLUDE_DIR} ${PTHREAD_INCLUDE_DIR})
link_directories(${mosquitto_SOURCE_DIR}/lib)

if (WITH_BUNDLED_DEPS)
        include_directories(${mosquitto_SOURCE_DIR} ${mosquitto_SOURCE_DIR}/deps)
endif (WITH_BUNDLED_DEPS)

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
	misc_mosq.c misc_mosq.h
	mosquitto.c ../include/mosquitto.h
	mosquitto_internal.h
	../include/mqtt_protocol.h
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
	strings_mosq.c
	thread_mosq.c
	time_mosq.c
	tls_mosq.c
	utf8_mosq.c
	util_mosq.c util_topic.c util_mosq.h
	will_mosq.c will_mosq.h)

set (LIBRARIES ${OPENSSL_LIBRARIES} ${PTHREAD_LIBRARIES})

if (UNIX AND NOT APPLE AND NOT ANDROID)
	find_library(LIBRT rt)
	if (LIBRT)
		set (LIBRARIES ${LIBRARIES} rt)
	endif (LIBRT)
endif (UNIX AND NOT APPLE AND NOT ANDROID)

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
)

target_link_libraries(libmosquitto ${LIBRARIES})

set_target_properties(libmosquitto PROPERTIES
	OUTPUT_NAME mosquitto
	VERSION ${VERSION}
	SOVERSION 1
)

install(TARGETS libmosquitto RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}" LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}")

if (WITH_STATIC_LIBRARIES)
	add_library(libmosquitto_static STATIC ${C_SRC})
	if (WITH_PIC)
		set_target_properties(libmosquitto_static PROPERTIES
			POSITION_INDEPENDENT_CODE 1
		)
	endif (WITH_PIC)

	target_link_libraries(libmosquitto_static ${LIBRARIES})

	set_target_properties(libmosquitto_static PROPERTIES
		OUTPUT_NAME mosquitto_static
		VERSION ${VERSION}
	)

	target_compile_definitions(libmosquitto_static PUBLIC "LIBMOSQUITTO_STATIC")
	install(TARGETS libmosquitto_static ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}")
endif (WITH_STATIC_LIBRARIES)

install(FILES ../include/mosquitto.h DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}")
install(FILES ../include/mqtt_protocol.h DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}")
