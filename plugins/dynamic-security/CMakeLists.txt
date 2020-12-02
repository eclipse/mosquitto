if (CJSON_FOUND AND WITH_TLS)
	add_definitions("-DWITH_CJSON")

	set( CLIENT_INC ${mosquitto_SOURCE_DIR} ${mosquitto_SOURCE_DIR}/include
		${STDBOOL_H_PATH} ${STDINT_H_PATH} ${PTHREAD_INCLUDE_DIR}
		${OPENSSL_INCLUDE_DIR} ${mosquitto_SOURCE_DIR}/deps
		${mosquitto_SOURCE_DIR}/src
		${CJSON_INCLUDE_DIRS} )

	set( CLIENT_DIR ${mosquitto_BINARY_DIR}/lib ${CJSON_DIR})

	include_directories(${CLIENT_INC})
	link_directories(${CLIENT_DIR} ${mosquitto_SOURCE_DIR})

	add_library(mosquitto_dynamic_security SHARED
		acl.c
		auth.c
		clients.c
		clientlist.c
		dynamic_security.h
		groups.c
		grouplist.c
		json_help.c
		json_help.h
		plugin.c
		roles.c
		rolelist.c
		sub_matches_sub.c)

	set_target_properties(mosquitto_dynamic_security PROPERTIES
		POSITION_INDEPENDENT_CODE 1
	)
	set_target_properties(mosquitto_dynamic_security PROPERTIES PREFIX "")

	target_link_libraries(mosquitto_dynamic_security ${CJSON_LIBRARIES})
	if(WIN32)
		target_link_libraries(mosquitto_dynamic_security mosquitto)
	endif(WIN32)

	install(TARGETS mosquitto_dynamic_security RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}" LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}")
endif()
