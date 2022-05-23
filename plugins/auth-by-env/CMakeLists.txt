include_directories(${mosquitto_SOURCE_DIR} ${mosquitto_SOURCE_DIR}/include
			${OPENSSL_INCLUDE_DIR} ${STDBOOL_H_PATH} ${STDINT_H_PATH})

add_library(mosquitto_auth_by_env MODULE mosquitto_auth_by_env.c)
set_target_properties(mosquitto_auth_by_env PROPERTIES
	POSITION_INDEPENDENT_CODE 1
)
set_target_properties(mosquitto_auth_by_env PROPERTIES PREFIX "")

# Don't install, these are example plugins only. XXX
#install(TARGETS mosquitto_auth_by_env RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}" LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}")
