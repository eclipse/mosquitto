add_executable(mosquitto
	conf.c
	conf_includedir.c
	context.c
	database.c
	handle_connack.c
	handle_connect.c
	handle_publish.c
	handle_subscribe.c
	handle_unsubscribe.c
	logging.c
	loop.c
	mosquitto.c
	net.c
	persist.c persist.h
	plugin.c
	read_handle.c
	subs.c
	security.c security_default.c
	send_connack.c
	send_suback.c
	signals.c
	sys_tree.c sys_tree.h
	websockets.c
)
target_include_directories(mosquitto PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
target_link_libraries(mosquitto PRIVATE libmosquitto_with_broker)

if (WIN32 OR CYGWIN)
	target_sources(mosquitto PRIVATE service.c)
endif (WIN32 OR CYGWIN)

if (UNIX)
	target_link_libraries(mosquitto PRIVATE dl m)
endif (UNIX)

if (UNIX)
	if (APPLE)
		set_target_properties(mosquitto PROPERTIES LINK_FLAGS "-Wl,-exported_symbols_list -Wl,${mosquitto_SOURCE_DIR}/src/linker-macosx.syms")
	else (APPLE)
		set_target_properties(mosquitto PROPERTIES LINK_FLAGS "-Wl,-dynamic-list=${mosquitto_SOURCE_DIR}/src/linker.syms")
	endif (APPLE)
endif (UNIX)

install(TARGETS mosquitto RUNTIME DESTINATION "${SBINDIR}" LIBRARY DESTINATION "${LIBDIR}")
install(FILES mosquitto_broker.h mosquitto_plugin.h DESTINATION "${INCLUDEDIR}")

if (${WITH_TLS} STREQUAL ON)
	find_package(OpenSSL REQUIRED)

	add_executable(mosquitto_passwd mosquitto_passwd.c)
	target_link_libraries(mosquitto_passwd  OpenSSL::SSL OpenSSL::Crypto)
	install(TARGETS mosquitto_passwd RUNTIME DESTINATION "${BINDIR}" LIBRARY DESTINATION "${LIBDIR}")
endif (${WITH_TLS} STREQUAL ON)

if (UNIX AND NOT APPLE)
	install(CODE "EXEC_PROGRAM(/sbin/ldconfig)")
endif (UNIX AND NOT APPLE)
