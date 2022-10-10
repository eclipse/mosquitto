set (PLUGIN_NAME mosquitto_deny_protocol_version)

add_library(${PLUGIN_NAME} MODULE
	${PLUGIN_NAME}.c
)

target_include_directories(${PLUGIN_NAME} PRIVATE
	"${OPENSSL_INCLUDE_DIR}"
	"${mosquitto_SOURCE_DIR}"
	"${mosquitto_SOURCE_DIR}/include"
)

set_target_properties(${PLUGIN_NAME} PROPERTIES
	PREFIX ""
	POSITION_INDEPENDENT_CODE 1
)

if(WIN32)
	target_link_libraries(${PLUGIN_NAME} PRIVATE mosquitto)
endif()

# Don't install, these are example plugins only.
#install(TARGETS ${PLUGIN_NAME} RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}" LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}")
