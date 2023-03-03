set (PLUGIN_NAME mosquitto_topic_jail)

add_library(${PLUGIN_NAME} MODULE
	${PLUGIN_NAME}.c
)

target_include_directories(${PLUGIN_NAME} PRIVATE
	"${mosquitto_SOURCE_DIR}/include"
)

link_directories(${mosquitto_SOURCE_DIR})

set_target_properties(${PLUGIN_NAME} PROPERTIES
	PREFIX ""
	POSITION_INDEPENDENT_CODE 1
)

target_link_libraries(${PLUGIN_NAME} PRIVATE mosquitto)

# Don't install, these are example plugins only.
#install(TARGETS ${PLUGIN_NAME} RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}" LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}")
