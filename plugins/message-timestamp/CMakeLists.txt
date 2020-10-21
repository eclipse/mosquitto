include_directories(${mosquitto_SOURCE_DIR} ${mosquitto_SOURCE_DIR}/include
			${STDBOOL_H_PATH} ${STDINT_H_PATH})

add_library(mosquitto_message_timestamp SHARED mosquitto_message_timestamp.c)
set_target_properties(mosquitto_message_timestamp PROPERTIES
	POSITION_INDEPENDENT_CODE 1
)
set_target_properties(mosquitto_message_timestamp PROPERTIES PREFIX "")

install(TARGETS mosquitto_message_timestamp RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}" LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}")
