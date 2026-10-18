if(WITH_CTRL_SHELL AND EDITLINE_FOUND)
	add_library(ctrl_shell_mock OBJECT
		ctrl_shell_mock.cpp
		ctrl_shell_mock.hpp
	)
	target_compile_definitions(ctrl_shell_mock PRIVATE
		WITH_CTRL_SHELL
		WITH_EDITLINE
	)

	target_include_directories(ctrl_shell_mock
		PUBLIC
			${mosquitto_SOURCE_DIR}
			${mosquitto_SOURCE_DIR}/include
			${mosquitto_SOURCE_DIR}/apps/mosquitto_ctrl
			${mosquitto_SOURCE_DIR}/test/mock
			${mosquitto_SOURCE_DIR}/test/mock/apps/mosquitto_ctrl
	)
	target_link_libraries(ctrl_shell_mock PRIVATE cjson GTest::gmock)
endif()
