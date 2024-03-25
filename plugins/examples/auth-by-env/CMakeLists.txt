set (PLUGIN_NAME mosquitto_auth_by_env)

add_mosquitto_plugin_no_install("${PLUGIN_NAME}" "${PLUGIN_NAME}.c" "" "libmosquitto_common")
