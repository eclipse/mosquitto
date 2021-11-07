if (CJSON_FOUND AND INC_BRIDGE_SUPPORT)
	add_definitions("-DWITH_CJSON")
	add_definitions("-DWITH_BRIDGE")

	set( CLIENT_INC ${mosquitto_SOURCE_DIR} ${mosquitto_SOURCE_DIR}/include
		${mosquitto_SOURCE_DIR}/lib
		${STDBOOL_H_PATH} ${STDINT_H_PATH} ${PTHREAD_INCLUDE_DIR}
		${OPENSSL_INCLUDE_DIR} ${mosquitto_SOURCE_DIR}/deps
		${mosquitto_SOURCE_DIR}/src
		${CJSON_INCLUDE_DIRS} )

	set( CLIENT_DIR ${mosquitto_BINARY_DIR}/lib ${CJSON_DIR})

	include_directories(${CLIENT_INC})
	link_directories(${CLIENT_DIR} ${mosquitto_SOURCE_DIR})

	add_library(mosquitto_dynamic_bridge MODULE
		dynamic_bridge.c
		dynamic_bridge.h
		json_help.c
		json_help.h
		plugin.c
    )

	set_target_properties(mosquitto_dynamic_bridge PROPERTIES
		POSITION_INDEPENDENT_CODE 1
	)
	set_target_properties(mosquitto_dynamic_bridge PROPERTIES PREFIX "")

	target_link_libraries(mosquitto_dynamic_bridge ${CJSON_LIBRARIES})
	if(WITH_TLS)
		target_link_libraries(mosquitto_dynamic_bridge ${OPENSSL_LIBRARIES})
	endif(WITH_TLS)
	if(WIN32)
		target_link_libraries(mosquitto_dynamic_bridge mosquitto)
	endif(WIN32)

	install(TARGETS mosquitto_dynamic_bridge
		RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
		LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    )
endif()
