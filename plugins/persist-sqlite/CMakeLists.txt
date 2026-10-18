if(SQLITE3_FOUND)
	set(PLUGIN_NAME "mosquitto_persist_sqlite")

	set(SRCLIST
		persist_sqlite.h
		util.h
		../../common/json_help.h
		base_msgs.c
		clients.c
		client_msgs.c
		common.c
		init.c
		../../common/json_help.c
		plugin.c
		restore.c
		retain_msgs.c
		subscriptions.c
		tick.c
		will.c
	)

	set(INCLIST
		"${CJSON_INCLUDE_DIRS}"
	)

	set(LINKLIST
		libmosquitto_common
		cjson
		SQLite::SQLite3
	)

	add_mosquitto_plugin("${PLUGIN_NAME}" "${SRCLIST}" "${INCLIST}" "${LINKLIST}")
endif()
