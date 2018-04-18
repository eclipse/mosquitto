add_executable(mosquitto
	bridge.c
	conf.c
	context.c
	database.c
	logging.c
	loop.c
	mosquitto.c
	net.c
	persist.c
	read_handle.c
	read_handle_client.c
	read_handle_server.c
	subs.c
	security.c
	security_default.c
	send_server.c
	sys_tree.c
	websockets.c
)
target_include_directories(mosquitto
	PRIVATE
	"${CMAKE_CURRENT_SOURCE_DIR}"
)

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

option(WITH_WEBSOCKETS
	"Include websockets support?" OFF)
if (${WITH_WEBSOCKETS} STREQUAL ON)
	target_compile_definitions(libmosquitto_with_broker PUBLIC WITH_WEBSOCKETS)
endif (${WITH_WEBSOCKETS} STREQUAL ON)

if (WIN32 OR CYGWIN)
	target_sources(mosquitto PRIVATE service.c)
endif (WIN32 OR CYGWIN)

# Check for getaddrinfo_a
include(CheckLibraryExists)
check_library_exists(anl getaddrinfo_a  "" HAVE_GETADDRINFO_A)
if (HAVE_GETADDRINFO_A)
	add_definitions(-DHAVE_GETADDRINFO_A)
	set (MOSQ_LIBS ${MOSQ_LIBS} anl)
endif (HAVE_GETADDRINFO_A)



if (UNIX)
	if (APPLE)
		target_link_libraries(mosquitto PRIVATE dl m)
	else (APPLE)
		target_link_libraries(mosquitto PRIVATE dl m)
		find_library(LIBRT rt)
		if (LIBRT)
			target_link_libraries(mosquitto PRIVATE rt)
		endif (LIBRT)
	endif (APPLE)
endif (UNIX)

if (WIN32)
	target_link_libraries(libmosquitto PRIVATE wsock32 ws2_32)
endif (WIN32)

if (${WITH_WEBSOCKETS} STREQUAL ON)
	target_link_libraries(libmosquitto PRIVATE websockets)
endif (${WITH_WEBSOCKETS} STREQUAL ON)

# Simple detect libuuid
if(NOT APPLE)
	FIND_PATH(UUID_HEADER uuid/uuid.h)
	if (UUID_HEADER)
		add_definitions(-DWITH_UUID)
		set (MOSQ_LIBS ${MOSQ_LIBS} uuid)
	endif (UUID_HEADER)
endif(NOT APPLE)

target_link_libraries(mosquitto ${MOSQ_LIBS})

if (UNIX)
	if (APPLE)
		set_target_properties(mosquitto PROPERTIES LINK_FLAGS "-Wl,-exported_symbols_list -Wl,${mosquitto_SOURCE_DIR}/src/linker-macosx.syms")
	else (APPLE)
		set_target_properties(mosquitto PROPERTIES LINK_FLAGS "-Wl,-dynamic-list=${mosquitto_SOURCE_DIR}/src/linker.syms")
	endif (APPLE)
endif (UNIX)

install(TARGETS mosquitto RUNTIME DESTINATION "${SBINDIR}" LIBRARY DESTINATION "${LIBDIR}")
install(FILES mosquitto_plugin.h DESTINATION "${INCLUDEDIR}")

if (${WITH_TLS} STREQUAL ON)
	find_package(OpenSSL REQUIRED)

	add_executable(mosquitto_passwd mosquitto_passwd.c)
	target_link_libraries(mosquitto_passwd  OpenSSL::SSL OpenSSL::Crypto)
	install(TARGETS mosquitto_passwd RUNTIME DESTINATION "${BINDIR}" LIBRARY DESTINATION "${LIBDIR}")
endif (${WITH_TLS} STREQUAL ON)

if (UNIX)
	install(CODE "EXEC_PROGRAM(/sbin/ldconfig)")
endif (UNIX)
