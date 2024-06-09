if(WITH_TLS)
	add_executable(mosquitto_ctrl
		mosquitto_ctrl.c mosquitto_ctrl.h
		broker.c
		client.c
		dynsec.c
		dynsec_client.c
		dynsec_group.c
		dynsec_role.c
		../mosquitto_passwd/get_password.c ../mosquitto_passwd/get_password.h
		options.c
		../../common/json_help.c ../../common/json_help.h
	)

	target_include_directories(mosquitto_ctrl PRIVATE
		"${mosquitto_SOURCE_DIR}"
		"${mosquitto_SOURCE_DIR}/apps/mosquitto_passwd"
		"${mosquitto_SOURCE_DIR}/common"
		"${mosquitto_SOURCE_DIR}/plugins/common"
		"${mosquitto_SOURCE_DIR}/plugins/dynamic-security"
	)
	if(WITH_BUNDLED_DEPS)
		target_include_directories(mosquitto_ctrl PRIVATE
			"${mosquitto_SOURCE_DIR}/deps"
		)
	endif()

	if(WITH_STATIC_LIBRARIES)
		target_link_libraries(mosquitto_ctrl PRIVATE libmosquitto_static)
	else()
		target_link_libraries(mosquitto_ctrl PRIVATE libmosquitto)
	endif()

	if(UNIX)
		if(APPLE)
			target_link_libraries(mosquitto_ctrl PRIVATE dl)
		elseif(${CMAKE_SYSTEM_NAME} MATCHES "OpenBSD")
			#
		elseif(${CMAKE_SYSTEM_NAME} MATCHES "NetBSD")
			#
		elseif(QNX)
			#
		else()
			target_link_libraries(mosquitto_ctrl PRIVATE dl)
		endif()
	endif()

	target_link_libraries(mosquitto_ctrl
	  PRIVATE
	  	common-options
		libmosquitto_common
		OpenSSL::SSL
		cJSON
	)

	if(WITH_THREADING)
		if(WIN32)
			target_link_libraries(mosquitto_ctrl PRIVATE PThreads4W::PThreads4W)
		else()
			set(THREADS_PREFER_PTHREAD_FLAG ON)
			find_package(Threads REQUIRED)
			target_link_libraries(mosquitto_ctrl PRIVATE Threads::Threads)
		endif()
	endif()


	install(TARGETS mosquitto_ctrl
		RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
	)
endif()
