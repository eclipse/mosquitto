set(BROKER_SRC
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
	persist_read_v234.c persist_read_v5.c persist_read.c
	persist_write_v5.c persist_write.c
	persist.h
	plugin_callbacks.c plugin_v5.c plugin_v4.c plugin_v3.c plugin_v2.c
	plugin_init.c plugin_cleanup.c plugin_persist.c
	plugin_acl_check.c plugin_basic_auth.c plugin_connect.c plugin_disconnect.c
	plugin_client_offline.c
	plugin_extended_auth.c plugin_message.c plugin_psk_key.c plugin_public.c
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
	websockets.c
	will_delay.c
	../lib/will_mosq.c ../lib/will_mosq.h
)

add_executable(mosquitto ${BROKER_SRC} main.c)

if (WITH_EMBEDD_BROKER)
	add_library(libmosquitto_broker SHARED ${BROKER_SRC})
endif()

function(broker_add_compile_definitions scope define)
	message(STATUS "broker_add_compile_definitions ${scope} ${define}") 
	target_compile_definitions(mosquitto ${scope} ${define})
	if (WITH_EMBEDD_BROKER)
		target_compile_definitions(libmosquitto_broker ${scope} ${define})
	endif()
endfunction()

function(broker_include_directories scope file)
	message(STATUS "broker_sources ${scope} ${file}") 
	target_include_directories(mosquitto ${scope} ${file})
	if (WITH_EMBEDD_BROKER)
		target_include_directories(libmosquitto_broker ${scope} ${file})
	endif()
endfunction()

function(broker_sources scope file)
	message(STATUS "broker_sources ${scope} ${file}") 
	target_sources(mosquitto ${scope} ${file})
	if (WITH_EMBEDD_BROKER)
		target_sources(libmosquitto_broker ${scope} ${file})
	endif()
endfunction()

function(broker_link_libraries scope library)
	message(STATUS "broker_link_libraries ${scope} ${library}") 
	target_link_libraries(mosquitto ${scope} ${library})
	if (WITH_EMBEDD_BROKER)
		target_link_libraries(libmosquitto_broker ${scope} ${library})
	endif()
endfunction()

CHECK_INCLUDE_FILES(sys/event.h HAVE_SYS_EVENT_H)
if(HAVE_SYS_EVENT_H)
	broker_add_compile_definitions(PRIVATE "WITH_KQUEUE")
endif()

find_path(HAVE_SYS_EPOLL_H sys/epoll.h)
if(HAVE_SYS_EPOLL_H)
	broker_add_compile_definitions(PRIVATE "WITH_EPOLL")
endif()

option(INC_BRIDGE_SUPPORT
	"Include bridge support for connecting to other brokers?" ON)
if(INC_BRIDGE_SUPPORT)
	broker_sources(PRIVATE bridge.c)
	broker_add_compile_definitions(PRIVATE "WITH_BRIDGE")
endif()


option(USE_LIBWRAP "Include tcp-wrappers support?" OFF)

if(USE_LIBWRAP)
	broker_sources(wrap)
	broker_add_compile_definitions(PRIVATE "WITH_WRAP")
endif()

option(INC_DB_UPGRADE "Include database upgrade support? (recommended)" ON)

if(INC_MEMTRACK)
	broker_add_compile_definitions(PUBLIC "WITH_MEMORY_TRACKING")
endif()

option(WITH_PERSISTENCE "Include persistence support?" ON)
if(WITH_PERSISTENCE)
	broker_add_compile_definitions(PRIVATE "WITH_PERSISTENCE")
endif()

option(WITH_SYS_TREE "Include $SYS tree support?" ON)
if(WITH_SYS_TREE)
	broker_add_compile_definitions(PRIVATE "WITH_SYS_TREE")
endif()

option(WITH_ADNS "Include ADNS support?" OFF)

if(CMAKE_SYSTEM_NAME STREQUAL Linux)
	option(WITH_SYSTEMD "Include systemd support?" OFF)
	if(WITH_SYSTEMD)
		broker_add_compile_definitions(PRIVATE "WITH_SYSTEMD")
		find_library(SYSTEMD_LIBRARY systemd)
		broker_link_libraries(PRIVATE "${SYSTEMD_LIBRARY}")
	endif()
endif()

option(STATIC_WEBSOCKETS "Use the static libwebsockets library?" OFF)

option(WITH_CONTROL "Include $CONTROL topic support?" ON)
if(WITH_CONTROL)
	broker_add_compile_definitions(PRIVATE "WITH_CONTROL")
endif()

if(WIN32 OR CYGWIN)
	broker_sources(PRIVATE service.c)
endif()

broker_add_compile_definitions(PRIVATE "WITH_BROKER")

if(WITH_TLS)
	broker_link_libraries(PRIVATE OpenSSL::SSL)
endif()
# Check for getaddrinfo_a
include(CheckLibraryExists)
check_library_exists(anl getaddrinfo_a  "" HAVE_GETADDRINFO_A)
if(HAVE_GETADDRINFO_A AND WITH_ADNS)
	broker_add_compile_definitions(PRIVATE "WITH_ADNS")
	broker_add_compile_definitions(PRIVATE "HAVE_GETADDRINFO_A")
	broker_link_libraries(PRIVATE anl)
endif()


if(UNIX)
	if(APPLE)
		broker_link_libraries(PRIVATE dl m)
	elseif (${CMAKE_SYSTEM_NAME} MATCHES "OpenBSD")
		broker_link_libraries(PRIVATE m)
	elseif (${CMAKE_SYSTEM_NAME} MATCHES "NetBSD")
		broker_link_libraries(PRIVATE m)
	elseif (${CMAKE_SYSTEM_NAME} MATCHES "Haiku")
		broker_link_libraries(PRIVATE network)
		broker_link_libraries(PRIVATE m)
	elseif(QNX)
		broker_link_libraries(PRIVATE socket)
		broker_link_libraries(PRIVATE m)
	else()
		broker_link_libraries(PRIVATE dl)
		broker_link_libraries(PRIVATE m)
		find_library(LIBRT rt)
		if(LIBRT)
			broker_link_libraries(PRIVATE rt)
		endif()
	endif()
endif()

if(WIN32)
	broker_link_libraries(PRIVATE ws2_32)
endif()

if(WITH_WEBSOCKETS)
	if(WITH_WEBSOCKETS_BUILTIN)
		broker_add_compile_definitions(PRIVATE "WITH_WEBSOCKETS=WS_IS_BUILTIN")
		broker_sources(PRIVATE "${mosquitto_SOURCE_DIR}/deps/picohttpparser/picohttpparser.c")
	else()
		find_package(libwebsockets)
		broker_add_compile_definitions(PRIVATE "WITH_WEBSOCKETS=WS_IS_LWS")
	endif()
endif()

if (ANDROID)
	broker_link_libraries(PRIVATE log)
endif (ANDROID)

if(WITH_WEBSOCKETS)
	if(WITH_WEBSOCKETS_BUILTIN)
		broker_include_directories(PRIVATE "${mosquitto_SOURCE_DIR}/deps/picohttpparser")
	else()
		if(STATIC_WEBSOCKETS)
			broker_link_libraries(PRIVATE websockets_static)
			if(WIN32)
				broker_link_libraries(PRIVATE iphlpapi)
			endif()
		else(STATIC_WEBSOCKETS)
			broker_link_libraries(PRIVATE websockets)
		endif()
	endif()
endif()

if(WITH_DLT)
	message(STATUS "DLT_LIBDIR = ${DLT_LIBDIR}")
	target_link_directories(mosquitto PRIVATE ${DLT_LIBDIR})
	broker_link_libraries(PRIVATE "${DLT_LIBRARIES}")
	broker_add_compile_definitions(PRIVATE "WITH_DLT")
endif()

broker_link_libraries(PRIVATE cJSON)

broker_include_directories(PUBLIC "${mosquitto_SOURCE_DIR}/include")
broker_include_directories(PRIVATE "${mosquitto_SOURCE_DIR}/common")
broker_include_directories(PRIVATE "${mosquitto_SOURCE_DIR}/lib")
broker_include_directories(PRIVATE "${mosquitto_SOURCE_DIR}/libcommon")
broker_include_directories(PRIVATE "${mosquitto_SOURCE_DIR}/src")

if(WITH_BUNDLED_DEPS)
	broker_include_directories(PRIVATE "${mosquitto_SOURCE_DIR}/deps")
endif()

broker_link_libraries(PUBLIC config-header)
broker_link_libraries(PUBLIC libmosquitto_common)
broker_link_libraries(PRIVATE common-options)

if (WITH_THREADING AND NOT WIN32)
	set(THREADS_PREFER_PTHREAD_FLAG ON)
	find_package(Threads REQUIRED)

	broker_link_libraries(PRIVATE Threads::Threads)
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

if (WITH_EMBEDD_BROKER)
	set_target_properties(libmosquitto_broker PROPERTIES
		OUTPUT_NAME mosquitto_broker
		VERSION ${VERSION}
		SOVERSION 1
		POSITION_INDEPENDENT_CODE 1
	)
	if(APPLE)
		set_target_properties(libmosquitto_broker PROPERTIES
			LINK_FLAGS "-Wl,-exported_symbols_list -Wl,${mosquitto_SOURCE_DIR}/src/broker-embedd-macos.syms"
		)
	else()
		set_target_properties(libmosquitto_broker PROPERTIES
			LINK_FLAGS "-Wl,-dynamic-list=${mosquitto_SOURCE_DIR}/src/broker-embedd.syms"
			)
	endif()

	install(FILES
		${mosquitto_SOURCE_DIR}/include/mosquitto/embedded_broker.h
		DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/mosquitto"
	)
	
	install(TARGETS libmosquitto_broker
		RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
		ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
		LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
	)
endif()

