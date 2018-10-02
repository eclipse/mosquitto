include_directories(${mosquitto_SOURCE_DIR} ${mosquitto_SOURCE_DIR}/src
		${mosquitto_SOURCE_DIR}/lib ${OPENSSL_INCLUDE_DIR}
		${STDBOOL_H_PATH} ${STDINT_H_PATH})

set (MOSQ_SRCS
	conf.c
	conf_includedir.c
	context.c
	database.c
	handle_connack.c
	handle_connect.c
	../lib/handle_ping.c
	../lib/handle_pubackcomp.c
	handle_publish.c
	../lib/handle_pubrec.c
	../lib/handle_pubrel.c
	../lib/handle_suback.c
	handle_subscribe.c
	../lib/handle_unsuback.c
	handle_unsubscribe.c
	lib_load.h
	logging.c
	loop.c
	../lib/memory_mosq.c ../lib/memory_mosq.h
	mosquitto.c
	mosquitto_broker.h mosquitto_broker_internal.h
	net.c
	../lib/net_mosq.c ../lib/net_mosq.h
	../lib/packet_mosq.c ../lib/packet_mosq.h
	persist.c persist.h
	plugin.c
	read_handle.c
	../lib/read_handle.h
	subs.c
	security.c security_default.c
	../lib/send_mosq.c ../lib/send_mosq.h
	send_connack.c
	../lib/send_connect.c
	../lib/send_disconnect.c
	../lib/send_publish.c
	send_suback.c
	signals.c
	../lib/send_subscribe.c
	../lib/send_unsubscribe.c
	sys_tree.c sys_tree.h
	../lib/time_mosq.c
	../lib/tls_mosq.c
	../lib/util_mosq.c ../lib/util_mosq.h
	../lib/utf8_mosq.c
	websockets.c
	../lib/will_mosq.c ../lib/will_mosq.h)


option(WITH_BUNDLED_DEPS "Build with bundled dependencies?" ON)
if (${WITH_BUNDLED_DEPS} STREQUAL ON)
	include_directories(${mosquitto_SOURCE_DIR} ${mosquitto_SOURCE_DIR}/src/deps)
endif (${WITH_BUNDLED_DEPS} STREQUAL ON)

option(INC_BRIDGE_SUPPORT
	"Include bridge support for connecting to other brokers?" ON)
if (${INC_BRIDGE_SUPPORT} STREQUAL ON)
	set (MOSQ_SRCS ${MOSQ_SRCS} bridge.c)
	add_definitions("-DWITH_BRIDGE")
endif (${INC_BRIDGE_SUPPORT} STREQUAL ON)


option(USE_LIBWRAP
	"Include tcp-wrappers support?" OFF)

if (${USE_LIBWRAP} STREQUAL ON)
	set (MOSQ_LIBS ${MOSQ_LIBS} wrap)
	add_definitions("-DWITH_WRAP")
endif (${USE_LIBWRAP} STREQUAL ON)

option(INC_DB_UPGRADE
	"Include database upgrade support? (recommended)" ON)

option(INC_MEMTRACK
	"Include memory tracking support?" ON)
if (${INC_MEMTRACK} STREQUAL ON)
	add_definitions("-DWITH_MEMORY_TRACKING")
endif (${INC_MEMTRACK} STREQUAL ON)

option(WITH_PERSISTENCE
	"Include persistence support?" ON)
if (${WITH_PERSISTENCE} STREQUAL ON)
	add_definitions("-DWITH_PERSISTENCE")
endif (${WITH_PERSISTENCE} STREQUAL ON)

option(WITH_SYS_TREE
	"Include $SYS tree support?" ON)
if (${WITH_SYS_TREE} STREQUAL ON)
	add_definitions("-DWITH_SYS_TREE")
endif (${WITH_SYS_TREE} STREQUAL ON)

if (CMAKE_SYSTEM_NAME STREQUAL Linux)
	option(WITH_SYSTEMD
		"Include systemd support?" OFF)
	if (${WITH_SYSTEMD} STREQUAL ON)
		add_definitions("-DWITH_SYSTEMD")
		find_library(SYSTEMD_LIBRARY systemd)
		set (MOSQ_LIBS ${MOSQ_LIBS} ${SYSTEMD_LIBRARY})
	endif (${WITH_SYSTEMD} STREQUAL ON)
endif (CMAKE_SYSTEM_NAME STREQUAL Linux)

option(WITH_WEBSOCKETS "Include websockets support?" OFF)
option(STATIC_WEBSOCKETS "Use the static libwebsockets library?" OFF)
if (${WITH_WEBSOCKETS} STREQUAL ON )
	add_definitions("-DWITH_WEBSOCKETS")
endif (${WITH_WEBSOCKETS} STREQUAL ON)

if (WIN32 OR CYGWIN)
	set (MOSQ_SRCS ${MOSQ_SRCS} service.c)
endif (WIN32 OR CYGWIN)

add_definitions (-DWITH_BROKER)

set (MOSQ_LIBS ${MOSQ_LIBS} ${OPENSSL_LIBRARIES})

# Check for getaddrinfo_a
include(CheckLibraryExists)
check_library_exists(anl getaddrinfo_a  "" HAVE_GETADDRINFO_A)
if (HAVE_GETADDRINFO_A)
	add_definitions(-DHAVE_GETADDRINFO_A)
	set (MOSQ_LIBS ${MOSQ_LIBS} anl)
endif (HAVE_GETADDRINFO_A)


if (UNIX)
	if (APPLE)
		set (MOSQ_LIBS ${MOSQ_LIBS} dl m)
    elseif(QNX)
        set(MOSQ_LIBS ${MOSQ_LIBS} m socket)
    else(APPLE)
        set (MOSQ_LIBS ${MOSQ_LIBS} dl m)
        find_library(LIBRT rt)
        if (LIBRT)
            set (MOSQ_LIBS ${MOSQ_LIBS} rt)
        endif (LIBRT)
    endif (APPLE)
endif (UNIX)

if (WIN32)
	set (MOSQ_LIBS ${MOSQ_LIBS} ws2_32)
endif (WIN32)

if (${WITH_WEBSOCKETS} STREQUAL ON)
	if (${STATIC_WEBSOCKETS} STREQUAL ON)
		set (MOSQ_LIBS ${MOSQ_LIBS} websockets_static)
		if (WIN32)
			set (MOSQ_LIBS ${MOSQ_LIBS} iphlpapi)
			link_directories(${mosquitto_SOURCE_DIR})
		endif (WIN32)
	else (${STATIC_WEBSOCKETS} STREQUAL ON)
		set (MOSQ_LIBS ${MOSQ_LIBS} websockets)
	endif (${STATIC_WEBSOCKETS} STREQUAL ON)
endif (${WITH_WEBSOCKETS} STREQUAL ON)

# Simple detect libuuid
if(NOT APPLE)
	FIND_PATH(UUID_HEADER uuid/uuid.h)
	if (UUID_HEADER)
		add_definitions(-DWITH_UUID)
		set (MOSQ_LIBS ${MOSQ_LIBS} uuid)
	endif (UUID_HEADER)
endif(NOT APPLE)

add_executable(mosquitto ${MOSQ_SRCS})
target_link_libraries(mosquitto ${MOSQ_LIBS})

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
	add_executable(mosquitto_passwd mosquitto_passwd.c)
	target_link_libraries(mosquitto_passwd ${OPENSSL_LIBRARIES})
	install(TARGETS mosquitto_passwd RUNTIME DESTINATION "${BINDIR}" LIBRARY DESTINATION "${LIBDIR}")
endif (${WITH_TLS} STREQUAL ON)

if (UNIX AND NOT APPLE)
	install(CODE "EXEC_PROGRAM(/sbin/ldconfig)")
endif (UNIX AND NOT APPLE)


