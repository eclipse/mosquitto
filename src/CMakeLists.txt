custom_add_executable(mosquitto
	acl_file.c acl_file.h
	../plugins/acl-file/acl_check.c
	../plugins/acl-file/acl_parse.c
	../lib/alias_mosq.c ../lib/alias_mosq.h
	bridge.c bridge_topic.c
	broker_control.c
	conf.c
	conf_includedir.c
	context.c
	control.c
	control_common.c
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
	mosquitto.c
	../include/mosquitto_broker.h mosquitto_broker_internal.h
	mux.c mux.h mux_epoll.c mux_kqueue.c mux_poll.c
	net.c
	../lib/net_mosq_ocsp.c ../lib/net_mosq.c ../lib/net_mosq.h
	../lib/net_ws.c
	../lib/packet_datatypes.c
	../lib/packet_mosq.c ../lib/packet_mosq.h
	password_file.c password_file.h
	../plugins/password-file/password_check.c
	../plugins/password-file/password_parse.c
	persist_read_v234.c persist_read_v5.c persist_read.c
	persist_write_v5.c persist_write.c
	persist.h
	plugin_callbacks.c plugin_v5.c plugin_v4.c plugin_v3.c plugin_v2.c
	plugin_init.c plugin_cleanup.c plugin_persist.c
	plugin_acl_check.c plugin_basic_auth.c plugin_connect.c plugin_disconnect.c
	plugin_client_offline.c
	plugin_extended_auth.c plugin_message.c plugin_psk_key.c plugin_public.c
	plugin_reload.c
	plugin_subscribe.c
	plugin_tick.c
	plugin_unsubscribe.c
	property_broker.c
	proxy_v1.c
	proxy_v2.c
	../lib/property_mosq.c ../lib/property_mosq.h
	psk_file.c
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
	subs.c
	sys_tree.c sys_tree.h
	../lib/tls_mosq.c
	topic_tok.c
	../lib/util_mosq.c ../lib/util_mosq.h
	watchdog.c
	websockets.c
	will_delay.c
	../lib/will_mosq.c ../lib/will_mosq.h
	xtreport.c
)

option_env(INC_BRIDGE_SUPPORT "Include bridge support for connecting to other brokers?" ON)
option_env(STATIC_WEBSOCKETS "Use the static libwebsockets library?" OFF)
option_env(USE_LIBWRAP "Include tcp-wrappers support?" OFF)
option_env(WITH_ADNS "Include ADNS support?" OFF)
option_env(WITH_CONTROL "Include $CONTROL topic support?" ON)
option_env(WITH_HTTP_API "Include http_api support for listeners?" ON)
option_env(WITH_OLD_KEEPALIVE "Use legacy keepalive check mechanism?" OFF)
option_env(WITH_PERSISTENCE "Include legacy persistence support?" ON)
option_env(WITH_PERSISTENCE "Include persistence support?" ON)
option_env(WITH_SYS_TREE "Include $SYS tree support?" ON)
option_env(WITH_XTREPORT "Include xtreport support (debugging only)?" OFF)

set(HTTP_API_DIR "Default http_api directory" CACHE STRING "")

# Check for getaddrinfo_a
# Prior to glibc 2.34 this required linking with anl
if(WITH_ADNS)
	cmake_push_check_state()
	set(ANL_CODE "
		#define _GNU_SOURCE
		#include <stdlib.h>
		#include <netdb.h>
		int main(){
			return getaddrinfo_a(0, NULL, 0, NULL);
		}
	")
	check_source_compiles(C "${ANL_CODE}" HAVE_GETADDRINFO_A)
	if(HAVE_GETADDRINFO_A)
		target_compile_definitions(mosquitto PRIVATE "WITH_ADNS")
	else()
		set(CMAKE_REQUIRED_LIBRARIES "anl")
		check_source_compiles(C "${ANL_CODE}" HAVE_GETADDRINFO_A_LIBANL)

		if(HAVE_GETADDRINFO_A_LIBANL)
			target_compile_definitions(mosquitto PRIVATE "WITH_ADNS")
			target_link_libraries(mosquitto PRIVATE anl)
		else()
			message(FATAL_ERROR "WITH_ADNS is set, but getaddrinfo_a() is not available.")
		endif()
	endif()
	cmake_pop_check_state()
endif()

if(INC_BRIDGE_SUPPORT)
	target_sources(mosquitto PRIVATE bridge.c)
	target_compile_definitions(mosquitto PRIVATE "WITH_BRIDGE")
endif()

if(WITH_CONTROL)
	target_compile_definitions(mosquitto PRIVATE "WITH_CONTROL")
endif()

if(WITH_DLT)
	message(STATUS "DLT_LIBDIR = ${DLT_LIBDIR}")
	target_link_directories(mosquitto PRIVATE ${DLT_LIBDIR})
	target_link_libraries(mosquitto PRIVATE ${DLT_LIBRARIES})
	target_compile_definitions(mosquitto PRIVATE "WITH_DLT")
endif()

if(WITH_HTTP_API)
	if(WIN32)
		find_library(libmicrohttpd_FOUND NAMES microhttpd-dll)
		set(LIBMICROHTTPD_LIBRARY "${libmicrohttpd_FOUND}")
	else()
		pkg_check_modules(libmicrohttpd IMPORTED_TARGET libmicrohttpd)
		set(LIBMICROHTTPD_LIBRARY PkgConfig::libmicrohttpd)
	endif()
	if(libmicrohttpd_FOUND)
		target_sources(mosquitto PRIVATE http_api.c)
		target_compile_definitions(mosquitto PRIVATE "WITH_HTTP_API")
		target_link_libraries(mosquitto PRIVATE ${LIBMICROHTTPD_LIBRARY})
		if(HTTP_API_DIR)
			target_compile_definitions(mosquitto PRIVATE "HTTP_API_DIR=\"${HTTP_API_DIR}\"")
		endif()
	else()
		message(WARNING "microhttpd not found, disabling WITH_HTTP_API")
	endif()
endif()

if(USE_LIBWRAP)
	target_link_libraries(mosquitto PRIVATE wrap)
	target_compile_definitions(mosquitto PRIVATE "WITH_WRAP")
endif()

if(INC_MEMTRACK)
	target_compile_definitions(mosquitto PUBLIC "WITH_MEMORY_TRACKING")
endif()

if(WITH_OLD_KEEPALIVE)
	add_definitions("-DWITH_OLD_KEEPALIVE")
endif(WITH_OLD_KEEPALIVE)

if(WITH_PERSISTENCE)
	target_compile_definitions(mosquitto PRIVATE "WITH_PERSISTENCE")
endif()

CHECK_INCLUDE_FILES(sys/event.h HAVE_SYS_EVENT_H)
if(HAVE_SYS_EVENT_H)
	target_compile_definitions(mosquitto PRIVATE "WITH_KQUEUE")
endif()

find_path(HAVE_SYS_EPOLL_H sys/epoll.h)
if(HAVE_SYS_EPOLL_H)
	target_compile_definitions(mosquitto PRIVATE "WITH_EPOLL")
endif()

if(WITH_SYS_TREE)
	target_compile_definitions(mosquitto PRIVATE "WITH_SYS_TREE")
endif()

if(WITH_SYS_TREE)
	target_compile_definitions(mosquitto PRIVATE "WITH_SYS_TREE")
endif()

if(CMAKE_SYSTEM_NAME STREQUAL Linux)
	option_env(WITH_SYSTEMD "Include systemd support?" OFF)
	if(WITH_SYSTEMD)
		target_compile_definitions(mosquitto PRIVATE "WITH_SYSTEMD")
		find_library(SYSTEMD_LIBRARY systemd)
		target_link_libraries(mosquitto PRIVATE ${SYSTEMD_LIBRARY})
	endif()
endif()

if (WITH_THREADING AND NOT WIN32)
	set(THREADS_PREFER_PTHREAD_FLAG ON)
	find_package(Threads REQUIRED)

	target_link_libraries(mosquitto PRIVATE Threads::Threads)
endif()

if(WITH_TLS)
	target_link_libraries(mosquitto PRIVATE OpenSSL::SSL)
endif()

if(WITH_WEBSOCKETS)
	if(WITH_WEBSOCKETS_BUILTIN)
		target_compile_definitions(mosquitto PRIVATE "WITH_WEBSOCKETS=WS_IS_BUILTIN")
		target_sources(mosquitto PRIVATE ${mosquitto_SOURCE_DIR}/deps/picohttpparser/picohttpparser.c)
		target_include_directories(mosquitto PRIVATE "${mosquitto_SOURCE_DIR}/deps/picohttpparser")
	else()
		find_package(libwebsockets)
		target_compile_definitions(mosquitto PRIVATE "WITH_WEBSOCKETS=WS_IS_LWS")
		if(STATIC_WEBSOCKETS)
			target_link_libraries(mosquitto PRIVATE websockets)
			if(WIN32)
				target_link_libraries(mosquitto PRIVATE iphlpapi)
			endif()
		else(STATIC_WEBSOCKETS)
			target_link_libraries(mosquitto PRIVATE websockets_shared)
		endif()
	endif()
endif()

if(WITH_XTREPORT)
	target_compile_definitions(mosquitto PRIVATE "WITH_XTREPORT")
endif()

if(WIN32 OR CYGWIN)
	target_sources(mosquitto PRIVATE service.c)
endif()

target_compile_definitions(mosquitto PRIVATE "WITH_BROKER")

if (ANDROID)
	target_link_libraries(mosquitto PRIVATE log)
endif (ANDROID)

if(UNIX)
	if(APPLE)
		target_link_libraries(mosquitto PRIVATE dl m)
	elseif (${CMAKE_SYSTEM_NAME} MATCHES "OpenBSD")
		target_link_libraries(mosquitto PRIVATE m)
	elseif (${CMAKE_SYSTEM_NAME} MATCHES "NetBSD")
		target_link_libraries(mosquitto PRIVATE m)
	elseif (${CMAKE_SYSTEM_NAME} MATCHES "Haiku")
		target_link_libraries(mosquitto PRIVATE m network)
	elseif(QNX)
		target_link_libraries(mosquitto PRIVATE m socket)
	else()
		target_link_libraries(mosquitto PRIVATE dl m)
	endif()
endif()

if(WIN32)
	target_link_libraries(mosquitto PRIVATE ws2_32)
endif()

target_link_libraries(mosquitto PRIVATE cjson)

target_include_directories(mosquitto
	PUBLIC
		"${mosquitto_SOURCE_DIR}/include"
	PRIVATE
		"${mosquitto_SOURCE_DIR}/common"
		"${mosquitto_SOURCE_DIR}/lib"
		"${mosquitto_SOURCE_DIR}/libcommon"
		"${mosquitto_SOURCE_DIR}/src"
		"${CJSON_INCLUDE_DIRS}"
)

target_link_libraries(mosquitto
	PUBLIC
		libmosquitto_common
	PRIVATE
		common-options
		${MOSQ_LIBS}
)

set_target_properties(mosquitto PROPERTIES
	ENABLE_EXPORTS 1
	ARCHIVE_OUTPUT_NAME "mosquitto_broker"
)

if(UNIX)
	if(APPLE)
		set_target_properties(mosquitto PROPERTIES
			LINK_FLAGS "-Wl,-exported_symbols_list -Wl,${mosquitto_SOURCE_DIR}/src/linker-macosx.syms"
		)
	elseif (AIX)
	else()
		set_target_properties(mosquitto PROPERTIES
			LINK_FLAGS "-Wl,-dynamic-list=${mosquitto_SOURCE_DIR}/src/linker.syms"
		)
	endif()
endif()

custom_install(TARGETS mosquitto
	RUNTIME DESTINATION "${CMAKE_INSTALL_SBINDIR}"
)
