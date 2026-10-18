if(WITH_TLS)
	set(SRC
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

	if(WITH_CTRL_SHELL AND LINEEDITING_FOUND)
		add_library(ctrl_shell OBJECT
			ctrl_shell.c
			ctrl_shell.h
			ctrl_shell_broker.c
			ctrl_shell_client.c
			ctrl_shell_completion_tree.c
			ctrl_shell_dynsec.c
			ctrl_shell_post_connect.c
			ctrl_shell_pre_connect.c
			ctrl_shell_printf.c
		)
		target_compile_definitions(ctrl_shell PRIVATE WITH_CTRL_SHELL)
		target_include_directories(ctrl_shell PRIVATE
			"${mosquitto_SOURCE_DIR}"
			"${mosquitto_SOURCE_DIR}/common"
			"${mosquitto_SOURCE_DIR}/include"
			"${CJSON_INCLUDE_DIRS}"
		)
		target_link_libraries(ctrl_shell PRIVATE
			LineEditing::LineEditing
			OpenSSL::SSL
		)

		add_library(ctrl_shell_io OBJECT
			ctrl_shell_io.c
		)
		target_compile_definitions(ctrl_shell_io PRIVATE WITH_CTRL_SHELL)
		target_include_directories(ctrl_shell_io PRIVATE
			"${mosquitto_SOURCE_DIR}"
			"${mosquitto_SOURCE_DIR}/common"
			"${mosquitto_SOURCE_DIR}/include"
			"${CJSON_INCLUDE_DIRS}"
		)
		target_link_libraries(ctrl_shell_io PRIVATE
			LineEditing::LineEditing
			OpenSSL::SSL
		)
	endif()
	custom_add_executable(mosquitto_ctrl ${SRC})

	target_include_directories(mosquitto_ctrl PRIVATE
		"${mosquitto_SOURCE_DIR}/apps/mosquitto_passwd"
		"${mosquitto_SOURCE_DIR}/common"
		"${mosquitto_SOURCE_DIR}/plugins/common"
		"${mosquitto_SOURCE_DIR}/plugins/dynamic-security"
		"${ARGON2_INCLUDE_DIRS}"
		"${CJSON_INCLUDE_DIRS}"
	)

	if(WITH_CTRL_SHELL AND LINEEDITING_FOUND)
		target_compile_definitions(mosquitto_ctrl PRIVATE WITH_CTRL_SHELL)
		target_link_libraries(mosquitto_ctrl PRIVATE
			LineEditing::LineEditing
			ctrl_shell
			ctrl_shell_io
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
		cjson
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


	custom_install(TARGETS mosquitto_ctrl
		RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
	)
endif()
