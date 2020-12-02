include_directories(${mosquitto_SOURCE_DIR} ${mosquitto_SOURCE_DIR}/src
		${mosquitto_SOURCE_DIR}/include ${mosquitto_SOURCE_DIR}/lib
		${OPENSSL_INCLUDE_DIR} ${STDBOOL_H_PATH} ${STDINT_H_PATH})

set (MOSQ_SRCS
	../lib/alias_mosq.c ../lib/alias_mosq.h
	bridge.c bridge_topic.c
	conf.c
	conf_includedir.c
	context.c
	control.c
	database.c
	handle_auth.c
	handle_connack.c
	handle_connect.c
	handle_disconnect.c
	../lib/handle_ping.c
	../lib/handle_pubackcomp.c
	handle_publish.c
	../lib/handle_pubrec.c
	../lib/handle_pubrel.c
	../lib/handle_suback.c
	handle_subscribe.c
	../lib/handle_unsuback.c
	handle_unsubscribe.c
	keepalive.c
	lib_load.h
	logging.c
	loop.c
	../lib/memory_mosq.c ../lib/memory_mosq.h
	memory_public.c
	mosquitto.c
	../include/mosquitto_broker.h mosquitto_broker_internal.h
	../lib/misc_mosq.c ../lib/misc_mosq.h
	mux.c mux.h mux_epoll.c mux_poll.c
	net.c
	../lib/net_mosq_ocsp.c ../lib/net_mosq.c ../lib/net_mosq.h
	../lib/packet_datatypes.c
	../lib/packet_mosq.c ../lib/packet_mosq.h
	password_mosq.c password_mosq.h
	persist_read_v234.c persist_read_v5.c persist_read.c
	persist_write_v5.c persist_write.c
	persist.h
	plugin.c plugin_public.c
	property_broker.c
	../lib/property_mosq.c ../lib/property_mosq.h
	read_handle.c
	../lib/read_handle.h
	retain.c
	security.c security_default.c
	../lib/send_mosq.c ../lib/send_mosq.h
	send_auth.c
	send_connack.c
	../lib/send_connect.c
	../lib/send_disconnect.c
	../lib/send_publish.c
	send_suback.c
	signals.c
	../lib/send_subscribe.c
	send_unsuback.c
	../lib/send_unsubscribe.c
	session_expiry.c
	../lib/strings_mosq.c
	subs.c
	sys_tree.c sys_tree.h
	../lib/time_mosq.c
	../lib/tls_mosq.c
	topic_tok.c
	../lib/util_mosq.c ../lib/util_topic.c ../lib/util_mosq.h
	../lib/utf8_mosq.c
	websockets.c
	will_delay.c
	../lib/will_mosq.c ../lib/will_mosq.h)


if (WITH_BUNDLED_DEPS)
	include_directories(${mosquitto_SOURCE_DIR} ${mosquitto_SOURCE_DIR}/deps)
endif (WITH_BUNDLED_DEPS)

option(INC_BRIDGE_SUPPORT
	"Include bridge support for connecting to other brokers?" ON)
if (INC_BRIDGE_SUPPORT)
	set (MOSQ_SRCS ${MOSQ_SRCS} bridge.c)
	add_definitions("-DWITH_BRIDGE")
endif (INC_BRIDGE_SUPPORT)


option(USE_LIBWRAP
	"Include tcp-wrappers support?" OFF)

if (USE_LIBWRAP)
	set (MOSQ_LIBS ${MOSQ_LIBS} wrap)
	add_definitions("-DWITH_WRAP")
endif (USE_LIBWRAP)

option(INC_DB_UPGRADE
	"Include database upgrade support? (recommended)" ON)

option(INC_MEMTRACK
	"Include memory tracking support?" ON)
if (INC_MEMTRACK)
	add_definitions("-DWITH_MEMORY_TRACKING")
endif (INC_MEMTRACK)

option(WITH_PERSISTENCE
	"Include persistence support?" ON)
if (WITH_PERSISTENCE)
	add_definitions("-DWITH_PERSISTENCE")
endif (WITH_PERSISTENCE)

option(WITH_SYS_TREE
	"Include $SYS tree support?" ON)
if (WITH_SYS_TREE)
	add_definitions("-DWITH_SYS_TREE")
endif (WITH_SYS_TREE)

option(WITH_ADNS
	"Include ADNS support?" OFF)

if (CMAKE_SYSTEM_NAME STREQUAL Linux)
	option(WITH_SYSTEMD
		"Include systemd support?" OFF)
	if (WITH_SYSTEMD)
		add_definitions("-DWITH_SYSTEMD")
		find_library(SYSTEMD_LIBRARY systemd)
		set (MOSQ_LIBS ${MOSQ_LIBS} ${SYSTEMD_LIBRARY})
	endif (WITH_SYSTEMD)
endif (CMAKE_SYSTEM_NAME STREQUAL Linux)

option(WITH_WEBSOCKETS "Include websockets support?" OFF)
option(STATIC_WEBSOCKETS "Use the static libwebsockets library?" OFF)
if (WITH_WEBSOCKETS)
	find_package(libwebsockets)
	add_definitions("-DWITH_WEBSOCKETS")
endif (WITH_WEBSOCKETS)

option(WITH_CONTROL "Include $CONTROL topic support?" ON)
if (WITH_CONTROL)
	add_definitions("-DWITH_CONTROL")
endif (WITH_CONTROL)


if (WIN32 OR CYGWIN)
	set (MOSQ_SRCS ${MOSQ_SRCS} service.c)
endif (WIN32 OR CYGWIN)

add_definitions (-DWITH_BROKER)

if (WITH_DLT)
    message(STATUS "DLT_LIBDIR = ${DLT_LIBDIR}")
    link_directories(${DLT_LIBDIR})
    set (MOSQ_LIBS ${MOSQ_LIBS} ${DLT_LIBRARIES})
endif (WITH_DLT)

set (MOSQ_LIBS ${MOSQ_LIBS} ${OPENSSL_LIBRARIES})
# Check for getaddrinfo_a
include(CheckLibraryExists)
check_library_exists(anl getaddrinfo_a  "" HAVE_GETADDRINFO_A)
if (HAVE_GETADDRINFO_A AND WITH_ADNS)
	add_definitions("-DWITH_ADNS")
	add_definitions(-DHAVE_GETADDRINFO_A)
	set (MOSQ_LIBS ${MOSQ_LIBS} anl)
endif (HAVE_GETADDRINFO_A AND WITH_ADNS)


if (UNIX)
	if (APPLE)
		set (MOSQ_LIBS ${MOSQ_LIBS} dl m)
    elseif (${CMAKE_SYSTEM_NAME} MATCHES "OpenBSD")
	    set (MOSQ_LIBS ${MOSQ_LIBS} m)
	elseif (${CMAKE_SYSTEM_NAME} MATCHES "NetBSD")
		set (MOSQ_LIBS ${MOSQ_LIBS} m)
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

if (WITH_WEBSOCKETS)
	if (STATIC_WEBSOCKETS)
		set (MOSQ_LIBS ${MOSQ_LIBS} websockets_static)
		if (WIN32)
			set (MOSQ_LIBS ${MOSQ_LIBS} iphlpapi)
			link_directories(${mosquitto_SOURCE_DIR})
		endif (WIN32)
	else (STATIC_WEBSOCKETS)
		set (MOSQ_LIBS ${MOSQ_LIBS} websockets)
	endif (STATIC_WEBSOCKETS)
endif (WITH_WEBSOCKETS)

add_executable(mosquitto ${MOSQ_SRCS})
target_link_libraries(mosquitto ${MOSQ_LIBS})
if (WIN32)
	set_target_properties(mosquitto PROPERTIES ENABLE_EXPORTS 1)
endif (WIN32)

if (UNIX)
	if (APPLE)
		set_target_properties(mosquitto PROPERTIES LINK_FLAGS "-Wl,-exported_symbols_list -Wl,${mosquitto_SOURCE_DIR}/src/linker-macosx.syms")
	else (APPLE)
		set_target_properties(mosquitto PROPERTIES LINK_FLAGS "-Wl,-dynamic-list=${mosquitto_SOURCE_DIR}/src/linker.syms")
	endif (APPLE)
endif (UNIX)

install(TARGETS mosquitto RUNTIME DESTINATION "${CMAKE_INSTALL_SBINDIR}")
install(FILES ../include/mosquitto_broker.h ../include/mosquitto_plugin.h DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}")
