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

option(INC_BRIDGE_SUPPORT
	"Include bridge support for connecting to other brokers?" ON)
if (${INC_BRIDGE_SUPPORT} STREQUAL ON)
	target_compile_definitions(mosquitto PRIVATE WITH_BRIDGE)
	target_sources(mosquitto PRIVATE bridge.c)
endif (${INC_BRIDGE_SUPPORT} STREQUAL ON)

option(USE_LIBWRAP
	"Include tcp-wrappers support?" OFF)

if (${USE_LIBWRAP} STREQUAL ON)
	target_compile_definitions(mosquitto PRIVATE WITH_WRAP)
	target_link_libraries(mosquitto PRIVATE wrap)
endif (${USE_LIBWRAP} STREQUAL ON)

option(INC_DB_UPGRADE
	"Include database upgrade support? (recommended)" ON)

option(INC_MEMTRACK
	"Include memory tracking support?" ON)
if (${INC_MEMTRACK} STREQUAL ON)
	target_compile_definitions(libmosquitto_with_broker PUBLIC WITH_MEMORY_TRACKING)
endif (${INC_MEMTRACK} STREQUAL ON)

option(WITH_PERSISTENCE
	"Include persistence support?" ON)
if (${WITH_PERSISTENCE} STREQUAL ON)
	target_compile_definitions(libmosquitto_with_broker PUBLIC WITH_PERSISTENCE)
endif (${WITH_PERSISTENCE} STREQUAL ON)

option(WITH_SYS_TREE
	"Include $SYS tree support?" ON)
if (${WITH_SYS_TREE} STREQUAL ON)
	target_compile_definitions(libmosquitto_with_broker PUBLIC WITH_SYS_TREE)
endif (${WITH_SYS_TREE} STREQUAL ON)

if (CMAKE_SYSTEM_NAME STREQUAL Linux)
	option(WITH_SYSTEMD
		"Include systemd support?" OFF)
	if (${WITH_SYSTEMD} STREQUAL ON)
		find_library(SYSTEMD_LIBRARY systemd)
		target_compile_definitions(mosquitto PRIVATE WITH_SYSTEMD)
		target_link_libraries(mosquitto PRIVATE ${SYSTEMD_LIBRARY})
	endif (${WITH_SYSTEMD} STREQUAL ON)
endif (CMAKE_SYSTEM_NAME STREQUAL Linux)

option(WITH_WEBSOCKETS
	"Include websockets support?" OFF)
if (${WITH_WEBSOCKETS} STREQUAL ON)
	target_compile_definitions(libmosquitto_with_broker PUBLIC WITH_WEBSOCKETS)
endif (${WITH_WEBSOCKETS} STREQUAL ON)

if (WIN32 OR CYGWIN)
	target_sources(mosquitto PRIVATE service.c)
endif (WIN32 OR CYGWIN)

# Check for getaddrinfo_a
option(WITH_GETADDRINFO_A "Include getaddrinfo_a support?" OFF)
if (${WITH_GETADDRINFO_A} STREQUAL ON)
	target_compile_definitions(libmosquitto_with_broker PUBLIC HAVE_GETADDRINFO_A)
	target_link_libraries(mosquitto PRIVATE anl)
endif (${WITH_GETADDRINFO_A} STREQUAL ON)

if (UNIX)
	target_link_libraries(mosquitto PRIVATE dl m)
	if (NOT APPLE)
		find_library(LIBRT rt)
		if (LIBRT)
			target_link_libraries(mosquitto PRIVATE rt)
		endif (LIBRT)
	endif (NOT APPLE)
endif (UNIX)

if (WIN32)
	target_link_libraries(libmosquitto_with_broker PRIVATE wsock32 ws2_32)
endif (WIN32)

if (${WITH_WEBSOCKETS} STREQUAL ON)
	target_link_libraries(libmosquitto_with_broker PRIVATE websockets)
endif (${WITH_WEBSOCKETS} STREQUAL ON)

# Simple detect libuuid
if(NOT APPLE)
	find_path(UUID_HEADER uuid/uuid.h)
	if (UUID_HEADER)
		target_compile_definitions(WITH_UUID)
		target_link_libraries(libmosquitto_with_broker PRIVATE uuid)
	endif (UUID_HEADER)
endif(NOT APPLE)

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
