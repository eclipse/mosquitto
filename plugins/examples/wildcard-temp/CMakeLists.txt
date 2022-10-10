set (PLUGIN_NAME mosquitto_wildcard_temp)

add_library(${PLUGIN_NAME} MODULE
	${PLUGIN_NAME}.c
)

target_include_directories(${PLUGIN_NAME} PRIVATE
	"${mosquitto_SOURCE_DIR}"
	"${mosquitto_SOURCE_DIR}/deps"
	"${mosquitto_SOURCE_DIR}/include"
)

if(WITH_BUNDLED_DEPS)
	target_include_directories(${PLUGIN_NAME} PRIVATE
		"${${PLUGIN_NAME}}/deps"
	)
endif()

set_target_properties(${PLUGIN_NAME} PROPERTIES
	PREFIX ""
	POSITION_INDEPENDENT_CODE 1
)

target_link_libraries(${PLUGIN_NAME} PRIVATE mosquitto)

# Don't install, these are example plugins only.
#install(TARGETS ${PLUGIN_NAME} RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}" LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}")
