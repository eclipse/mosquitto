if(SQLITE3_FOUND)
	set(PLUGIN_NAME "mosquitto_persist_sqlite")

	set(SRCLIST
		base_msgs.c
		clients.c
		client_msgs.c
		common.c
		init.c
		../../common/json_help.c ../../common/json_help.h
		plugin.c
		restore.c
		retain_msgs.c
		subscriptions.c
		tick.c
	)

	set(INCLIST )

	set(LINKLIST
		cJSON
		SQLite::SQLite3
	)

	plugin_helper("${PLUGIN_NAME}" "${SRCLIST}" "${INCLIST}" "${LINKLIST}")
endif()
