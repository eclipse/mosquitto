if(WITH_TLS)
	set(PLUGIN_NAME mosquitto_dynamic_security)

	set(SRCLIST
		acl.c
		auth.c
		clients.c
		clientlist.c
		config.c
		config_init.c
		control.c
		default_acl.c
		dynamic_security.h
		groups.c
		grouplist.c
		../../common/json_help.c ../../common/json_help.h
		kicklist.c
		plugin.c
		roles.c
		rolelist.c
		tick.c
	)

	set(INCLIST
		"${CJSON_INCLUDE_DIRS}"
		"${mosquitto_SOURCE_DIR}/lib"
		"${mosquitto_SOURCE_DIR}/src"
	)

	set(LINKLIST
		libmosquitto_common
		cJSON
		OpenSSL::SSL
	)

	if(ARGON2_FOUND)
		set(LINKLIST
			"${LINKLIST}"
			argon2
		)
	endif()
	add_mosquitto_plugin("${PLUGIN_NAME}" "${SRCLIST}" "${INCLIST}" "${LINKLIST}")
endif()
