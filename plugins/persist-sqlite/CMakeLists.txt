if(SQLITE3_FOUND AND CJSON_FOUND)
	set(CLIENT_INC
		"${STDBOOL_H_PATH}"
		"${STDINT_H_PATH}"
		"${mosquitto_SOURCE_DIR}/deps"
		"${mosquitto_SOURCE_DIR}/include"
		"${mosquitto_SOURCE_DIR}/src"
	)

	add_library(mosquitto_persist_sqlite MODULE
		base_msgs.c
		clients.c
		client_msgs.c
		init.c
		plugin.c
		restore.c
		retain_msgs.c
		subscriptions.c
		tick.c
	)

	target_include_directories(mosquitto_persist_sqlite PRIVATE
		${CLIENT_INC}
	)

	set_target_properties(mosquitto_persist_sqlite PROPERTIES
		PREFIX ""
		POSITION_INDEPENDENT_CODE 1
	)

	target_link_libraries(mosquitto_persist_sqlite
		PRIVATE
			SQLite::SQLite3
			cJSON
	)
	target_link_libraries(mosquitto_persist_sqlite PRIVATE mosquitto)

	install(TARGETS mosquitto_persist_sqlite
		RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
		LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
	)
endif()
