if (WITH_TLS AND CJSON_FOUND)
	add_definitions("-DWITH_CJSON")

	include_directories(${mosquitto_SOURCE_DIR} ${mosquitto_SOURCE_DIR}/include
			${mosquitto_SOURCE_DIR}/lib ${mosquitto_SOURCE_DIR}/src
			${OPENSSL_INCLUDE_DIR} ${STDBOOL_H_PATH} ${STDINT_H_PATH}
			${CJSON_INCLUDE_DIRS} ${mosquitto_SOURCE_DIR}/apps/mosquitto_passwd)

	link_directories(${CJSON_DIR})

	add_executable(mosquitto_ctrl
		mosquitto_ctrl.c mosquitto_ctrl.h
		client.c
		dynsec.c
		dynsec_client.c
		dynsec_group.c
		dynsec_role.c
		../mosquitto_passwd/get_password.c ../mosquitto_passwd/get_password.h
		../../lib/memory_mosq.c ../../lib/memory_mosq.h
		../../src/memory_public.c
		options.c
		../../src/password_mosq.c ../../src/password_mosq.h
		)

	if (WITH_STATIC_LIBRARIES)
		target_link_libraries(mosquitto_ctrl libmosquitto_static)
	else()
		target_link_libraries(mosquitto_ctrl libmosquitto)
	endif()

	if (UNIX)
		if (APPLE)
			target_link_libraries(mosquitto_ctrl dl)
		elseif (${CMAKE_SYSTEM_NAME} MATCHES "OpenBSD")
			#
		elseif (${CMAKE_SYSTEM_NAME} MATCHES "NetBSD")
			#
		elseif(QNX)
			#
		else(APPLE)
			target_link_libraries(mosquitto_ctrl dl)
		endif (APPLE)
	endif (UNIX)

	target_link_libraries(mosquitto_ctrl ${OPENSSL_LIBRARIES} ${CJSON_LIBRARIES})

	install(TARGETS mosquitto_ctrl RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}")
endif (WITH_TLS AND CJSON_FOUND)
