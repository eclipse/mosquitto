set (MOSQ_SRCS
	../lib/alias_mosq.c ../lib/alias_mosq.h
	../common/base64_mosq.c ../common/base64_mosq.h
	bridge.c bridge_topic.c
	broker_control.c
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
	http_serv.c
	../common/json_help.c ../common/json_help.h
	keepalive.c
	../common/lib_load.h
	listeners.c
	logging.c
	loop.c
	../lib/memory_mosq.c ../lib/memory_mosq.h
	memory_public.c
	mosquitto.c
	../include/mosquitto_broker.h mosquitto_broker_internal.h
	../common/misc_mosq.c ../common/misc_mosq.h
	mux.c mux.h mux_epoll.c mux_kqueue.c mux_poll.c
	net.c
	../lib/net_mosq_ocsp.c ../lib/net_mosq.c ../lib/net_mosq.h
	../lib/net_ws.c
	../lib/packet_datatypes.c
	../lib/packet_mosq.c ../lib/packet_mosq.h
	../common/password_mosq.c ../common/password_mosq.h
	persist_read_v234.c persist_read_v5.c persist_read.c
	persist_write_v5.c persist_write.c
	persist.h
	plugin_callbacks.c plugin_v5.c plugin_v4.c plugin_v3.c plugin_v2.c
	plugin_init.c plugin_cleanup.c plugin_persist.c
	plugin_acl_check.c plugin_basic_auth.c plugin_connect.c plugin_disconnect.c
	plugin_extended_auth.c plugin_message.c plugin_psk_key.c plugin_public.c
	plugin_subscribe.c
	plugin_tick.c
	plugin_unsubscribe.c
	property_broker.c
	../lib/property_mosq.c ../lib/property_mosq.h
	read_handle.c
	../lib/read_handle.h
	retain.c
	security_default.c
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
	../common/time_mosq.c ../common/time_mosq.h
	../lib/tls_mosq.c
	topic_tok.c
	../lib/util_mosq.c ../lib/util_topic.c ../lib/util_mosq.h
	../lib/utf8_mosq.c
	websockets.c
	will_delay.c
	../lib/will_mosq.c ../lib/will_mosq.h
)

CHECK_INCLUDE_FILES(sys/event.h HAVE_SYS_EVENT_H)
if(HAVE_SYS_EVENT_H)
	add_definitions("-DWITH_KQUEUE")
endif()

find_path(HAVE_SYS_EPOLL_H sys/epoll.h)
if(HAVE_SYS_EPOLL_H)
	add_definitions("-DWITH_EPOLL")
endif()

option(INC_BRIDGE_SUPPORT
	"Include bridge support for connecting to other brokers?" ON)
if(INC_BRIDGE_SUPPORT)
	set (MOSQ_SRCS ${MOSQ_SRCS} bridge.c)
	add_definitions("-DWITH_BRIDGE")
endif()


option(USE_LIBWRAP "Include tcp-wrappers support?" OFF)

if(USE_LIBWRAP)
	set (MOSQ_LIBS ${MOSQ_LIBS} wrap)
	add_definitions("-DWITH_WRAP")
endif()

option(INC_DB_UPGRADE "Include database upgrade support? (recommended)" ON)

option(INC_MEMTRACK "Include memory tracking support?" ON)
if(INC_MEMTRACK)
	add_definitions("-DWITH_MEMORY_TRACKING")
endif()

option(WITH_PERSISTENCE "Include persistence support?" ON)
if(WITH_PERSISTENCE)
	add_definitions("-DWITH_PERSISTENCE")
endif()

option(WITH_SYS_TREE "Include $SYS tree support?" ON)
if(WITH_SYS_TREE)
	add_definitions("-DWITH_SYS_TREE")
endif()

option(WITH_ADNS "Include ADNS support?" OFF)

if(CMAKE_SYSTEM_NAME STREQUAL Linux)
	option(WITH_SYSTEMD "Include systemd support?" OFF)
	if(WITH_SYSTEMD)
		add_definitions("-DWITH_SYSTEMD")
		find_library(SYSTEMD_LIBRARY systemd)
		set (MOSQ_LIBS ${MOSQ_LIBS} ${SYSTEMD_LIBRARY})
	endif()
endif()

option(STATIC_WEBSOCKETS "Use the static libwebsockets library?" OFF)

option(WITH_CONTROL "Include $CONTROL topic support?" ON)
if(WITH_CONTROL)
	add_definitions("-DWITH_CONTROL")
endif()


if(WIN32 OR CYGWIN)
	set (MOSQ_SRCS ${MOSQ_SRCS} service.c)
endif()

add_definitions (-DWITH_BROKER)

if(WITH_TLS)
	set (MOSQ_LIBS ${MOSQ_LIBS} OpenSSL::SSL)
endif()
# Check for getaddrinfo_a
include(CheckLibraryExists)
check_library_exists(anl getaddrinfo_a  "" HAVE_GETADDRINFO_A)
if(HAVE_GETADDRINFO_A AND WITH_ADNS)
	add_definitions("-DWITH_ADNS")
	add_definitions(-DHAVE_GETADDRINFO_A)
	set (MOSQ_LIBS ${MOSQ_LIBS} anl)
endif()


if(UNIX)
	if(APPLE)
		set (MOSQ_LIBS ${MOSQ_LIBS} dl m)
    elseif (${CMAKE_SYSTEM_NAME} MATCHES "OpenBSD")
	    set (MOSQ_LIBS ${MOSQ_LIBS} m)
	elseif (${CMAKE_SYSTEM_NAME} MATCHES "NetBSD")
		set (MOSQ_LIBS ${MOSQ_LIBS} m)
	elseif (${CMAKE_SYSTEM_NAME} MATCHES "Haiku")
	    set (MOSQ_LIBS ${MOSQ_LIBS} m network)
    elseif(QNX)
        set(MOSQ_LIBS ${MOSQ_LIBS} m socket)
    else()
        set (MOSQ_LIBS ${MOSQ_LIBS} dl m)
        find_library(LIBRT rt)
        if(LIBRT)
            set (MOSQ_LIBS ${MOSQ_LIBS} rt)
        endif()
    endif()
endif()

if(WIN32)
	set (MOSQ_LIBS ${MOSQ_LIBS} ws2_32)
endif()

if(WITH_WEBSOCKETS)
	if(WITH_WEBSOCKETS_BUILTIN)
		add_definitions("-DWITH_WEBSOCKETS=WS_IS_BUILTIN")
		set(MOSQ_SRCS ${MOSQ_SRCS} ${mosquitto_SOURCE_DIR}/deps/picohttpparser/picohttpparser.c)
	else()
		find_package(libwebsockets)
		add_definitions("-DWITH_WEBSOCKETS=WS_IS_LWS")
	endif()
endif()

add_executable(mosquitto ${MOSQ_SRCS})

if(WITH_WEBSOCKETS)
	if(WITH_WEBSOCKETS_BUILTIN)
		target_include_directories(mosquitto PRIVATE
			"${mosquitto_SOURCE_DIR}/deps/picohttpparser")
	else()
		if(STATIC_WEBSOCKETS)
			set (MOSQ_LIBS ${MOSQ_LIBS} websockets_static)
			if(WIN32)
				set (MOSQ_LIBS ${MOSQ_LIBS} iphlpapi)
			endif()
		else(STATIC_WEBSOCKETS)
			set (MOSQ_LIBS ${MOSQ_LIBS} websockets)
		endif()
	endif()
endif()

if(WITH_DLT)
    message(STATUS "DLT_LIBDIR = ${DLT_LIBDIR}")
    target_link_directories(mosquitto PRIVATE ${DLT_LIBDIR})
    set (MOSQ_LIBS ${MOSQ_LIBS} ${DLT_LIBRARIES})
	target_compile_definitions(mosquitto PRIVATE "WITH_DLT")
endif()

if(CJSON_FOUND)
	target_link_libraries(mosquitto PRIVATE cJSON)
endif()

target_include_directories(mosquitto
	PUBLIC
		"${mosquitto_SOURCE_DIR}/include"
	PRIVATE
		"${mosquitto_SOURCE_DIR}/common"
		"${mosquitto_SOURCE_DIR}/lib"
		"${mosquitto_SOURCE_DIR}/src"
)
if(WITH_BUNDLED_DEPS)
	target_include_directories(mosquitto PRIVATE
		"${mosquitto_SOURCE_DIR}/deps"
	)
endif()

target_link_libraries(mosquitto
	PUBLIC
		config-header
	PRIVATE
		common-options
		${MOSQ_LIBS}
)

if (WITH_THREADING AND NOT WIN32)
	set(THREADS_PREFER_PTHREAD_FLAG ON)
	find_package(Threads REQUIRED)

	target_link_libraries(mosquitto PRIVATE Threads::Threads)
endif()

set_target_properties(mosquitto PROPERTIES
	ENABLE_EXPORTS 1
)

if(UNIX)
	if(APPLE)
		set_target_properties(mosquitto PROPERTIES
			LINK_FLAGS "-Wl,-exported_symbols_list -Wl,${mosquitto_SOURCE_DIR}/src/linker-macosx.syms"
		)
	else()
		set_target_properties(mosquitto PROPERTIES
			LINK_FLAGS "-Wl,-dynamic-list=${mosquitto_SOURCE_DIR}/src/linker.syms"
		)
	endif()
endif()

install(TARGETS mosquitto
	RUNTIME DESTINATION "${CMAKE_INSTALL_SBINDIR}"
)
install(
	FILES
	${mosquitto_SOURCE_DIR}/include/mosquitto_broker.h
	${mosquitto_SOURCE_DIR}/include/mosquitto_plugin.h
	DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
)
