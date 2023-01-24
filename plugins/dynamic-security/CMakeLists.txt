if(CJSON_FOUND AND WITH_TLS)
	set(CLIENT_INC
		"${CJSON_INCLUDE_DIRS}"
		"${mosquitto_SOURCE_DIR}"
		"${mosquitto_SOURCE_DIR}/common"
		"${mosquitto_SOURCE_DIR}/deps"
		"${mosquitto_SOURCE_DIR}/include"
		"${mosquitto_SOURCE_DIR}/lib"
		"${mosquitto_SOURCE_DIR}/plugins/common"
		"${mosquitto_SOURCE_DIR}/src"
	)

	set(CLIENT_DIR "${mosquitto_BINARY_DIR}/lib" "${CJSON_DIR}")

	add_library(mosquitto_dynamic_security MODULE
		acl.c
		auth.c
		../../common/base64_mosq.c ../../common/base64_mosq.h
		clients.c
		clientlist.c
		config.c
		config_init.c
		control.c
		../../common/control_common.c ../../common/control_common.h
		default_acl.c
		dynamic_security.h
		groups.c
		grouplist.c
		hash.c
		../../common/json_help.c ../../common/json_help.h
		kicklist.c
		../../common/misc_mosq.c ../../common/misc_mosq.h
		../../common/password_mosq.c ../../common/password_mosq.h
		plugin.c
		roles.c
		rolelist.c
		yaml_help.c
		tick.c
	)

	target_include_directories(mosquitto_dynamic_security PRIVATE
		${CLIENT_INC}
	)
	if(WITH_BUNDLED_DEPS)
		target_include_directories(mosquitto_dynamic_security PRIVATE
			"${mosquitto_SOURCE_DIR}/deps"
		)
	endif()

	set_target_properties(mosquitto_dynamic_security PROPERTIES
		PREFIX ""
		POSITION_INDEPENDENT_CODE 1
	)

	target_link_libraries(mosquitto_dynamic_security
		PRIVATE
			common-options
			cJSON
			OpenSSL::SSL
	)
	target_link_libraries(mosquitto_dynamic_security PRIVATE mosquitto)
	if(WIN32)
		install(TARGETS mosquitto_dynamic_security
			DESTINATION "${CMAKE_INSTALL_BINDIR}")
	else()
		install(TARGETS mosquitto_dynamic_security
			RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
			LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}")
	endif()

endif()
