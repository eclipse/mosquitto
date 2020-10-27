set( CLIENT_INC ${mosquitto_SOURCE_DIR} ${mosquitto_SOURCE_DIR}/include
            ${STDBOOL_H_PATH} ${STDINT_H_PATH} ${PTHREAD_INCLUDE_DIR}
            ${OPENSSL_INCLUDE_DIR})

set( CLIENT_DIR ${mosquitto_BINARY_DIR}/lib)

if (CJSON_FOUND)
	set( CLIENT_DIR "${CLIENT_DIR} ${CJSON_DIR}" )
	set( CLIENT_INC "${CLIENT_INC};${CJSON_INCLUDE_DIRS}" )
endif()

include_directories(${CLIENT_INC})
link_directories(${CLIENT_DIR})

add_library(mosquitto_dynamic_security SHARED
	acl.c
	auth.c
	clients.c
	dynamic_security.h
	groups.c
	json_help.c
	json_help.h
	plugin.c
	roles.c
	sub_matches_sub.c)

set_target_properties(mosquitto_dynamic_security PROPERTIES
	POSITION_INDEPENDENT_CODE 1
)
set_target_properties(mosquitto_dynamic_security PROPERTIES PREFIX "")

if (CJSON_FOUND)
	target_link_libraries(mosquitto_dynamic_security ${CJSON_LIBRARIES})
endif()

install(TARGETS mosquitto_dynamic_security RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}" LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}")
