set (PLUGIN_NAME mosquitto_delayed_auth)

add_mosquitto_plugin_no_install("${PLUGIN_NAME}" "${PLUGIN_NAME}.c" "" "libmosquitto_common")
