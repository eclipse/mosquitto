# This is a cmake script. Process it with the CMake gui or command line utility
# to produce makefiles / Visual Studio project files on Mac OS X and Windows.
#
# To configure the build options either use the CMake gui, or run the command
# line utility including the "-i" option.

cmake_minimum_required(VERSION 3.24)

set (VERSION 2.1.2)
project(mosquitto
	VERSION ${VERSION}
	DESCRIPTION "Eclipse Mosquitto"
	LANGUAGES C
)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

list(APPEND CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake/")

add_definitions (-DCMAKE -DVERSION=\"${VERSION}\")

if(WIN32)
	add_definitions("-D_CRT_SECURE_NO_WARNINGS")
	add_definitions("-D_CRT_NONSTDC_NO_DEPRECATE")
endif()

if(APPLE)
	set(CMAKE_MODULE_LINKER_FLAGS "${CMAKE_MODULE_LINKER_FLAGS} -undefined dynamic_lookup")
endif()

set_property(GLOBAL PROPERTY TEST_ENV_VARS "BUILD_ROOT=${CMAKE_BINARY_DIR}")
function(option_env name description value)
	option(${name} "${description}" ${value})
	get_property(test_vars GLOBAL PROPERTY TEST_ENV_VARS)
	set_property(GLOBAL PROPERTY TEST_ENV_VARS "${test_vars};${name}=${${name}}")
endfunction()

add_library(common-options INTERFACE)
if(NOT WIN32)
	target_compile_options(common-options INTERFACE -Wall -Wextra -Wconversion)
endif()

include(CMakePushCheckState)
include(CheckIncludeFiles)
include(CheckLibraryExists)
include(CheckSourceCompiles)
include(GNUInstallDirs)
include(CMakePushCheckState)
include(CheckSourceCompiles)

find_package(cJSON CONFIG REQUIRED)
find_package(argon2)

option_env(INC_MEMTRACK "Include memory tracking support?" ON)
option_env(WITH_BUNDLED_DEPS "Build with bundled dependencies?" ON)
option_env(WITH_CTRL_SHELL "Include mosquitto_ctrl interactive shell support?" ON)
option_env(WITH_DLT "Include DLT support?" OFF)
option_env(WITH_FUZZING "Build fuzzers instead of normal executables?" OFF)
option_env(WITH_JEMALLOC "Build using the jemalloc memory allocator?" OFF)
option_env(WITH_LIB_CPP "Build C++ library?" ON)
option_env(WITH_LTO "Build with link time optimizations (IPO) / interprocedural optimization (IPO) enabled." ON)
option_env(WITH_PARALLEL_TESTS "Run tests in parallel?" ON)
option_env(WITH_PIC "Build the static library with PIC (Position Independent Code) enabled archives?" OFF)
option_env(WITH_SOCKS "Include SOCKS5 support?" ON)
option_env(WITH_SRV "Include SRV lookup support?" OFF)
option_env(WITH_STATIC_LIBRARIES "Build static versions of the libmosquitto/pp libraries?" OFF)
option_env(WITH_TESTS "Enable tests" ON)
option_env(WITH_THREADING "Include threading support?" ON)
option_env(WITH_TLS "Include SSL/TLS support?" ON)
option_env(WITH_TLS_PSK "Include TLS-PSK support (requires WITH_TLS)?" ON)
option_env(WITH_UNIX_SOCKETS "Include Unix Domain Socket support?" ON)
option_env(WITH_WEBSOCKETS "Include websockets support?" ON)
option_env(WITH_WEBSOCKETS_BUILTIN "Websockets support uses builtin library? Set OFF to use libwebsockets" ON)

set(LIB_TYPE_PLUGIN MODULE)
set(LIB_TYPE_LIBRARY SHARED)

if(WITH_FUZZING)
	set(WITH_TESTS OFF)
	set(LIB_TYPE_LIBRARY STATIC)
	set(LIB_TYPE_PLUGIN STATIC)
	add_compile_definitions(WITH_FUZZING)
endif()

function(custom_add_executable EXE)
	if(WITH_FUZZING)
		add_library(${EXE} STATIC ${ARGN})
		set_target_properties(${EXE} PROPERTIES
			PREFIX ""
			POSITION_INDEPENDENT_CODE 1
		)
	else()
		add_executable(${EXE} ${ARGN})
	endif()
endfunction()

function(custom_install)
	if(NOT WITH_FUZZING)
		install(${NARGS})
	endif()
endfunction()

if(ARGON2_FOUND)
	# Disable until separate password handling thread is implemented
	#add_definitions("-DWITH_ARGON2")
endif()

if(WITH_CTRL_SHELL)
	find_package(LineEditing)
endif()

message(STATUS "WITH_DLT = ${WITH_DLT}")
if(WITH_DLT)
	find_package(PkgConfig)
	pkg_check_modules(DLT "automotive-dlt >= 2.11" REQUIRED)
endif()

if(WITH_LIB_CPP OR WITH_TESTS)
	ENABLE_LANGUAGE(CXX)
endif()

if(WITH_LTO)
	include(CheckIPOSupported)
	check_ipo_supported(RESULT is_ipo_supported OUTPUT output)
	if(is_ipo_supported)
		set_property(TARGET common-options PROPERTY INTERPROCEDURAL_OPTIMIZATION TRUE)
	else()
		message(WARNING "LTO/IPO is not supported: ${output}")
	endif()
endif()

if(WITH_SOCKS)
	add_definitions("-DWITH_SOCKS")
endif()

if(WITH_THREADING)
	add_definitions("-DWITH_THREADING")
	if(WIN32)
		find_package(PThreads4W REQUIRED)
		set (THREADLIB PThreads4W::PThreads4W)
	else()
		set(THREADS_PREFER_PTHREAD_FLAG ON)
		find_package(Threads REQUIRED)
		set (THREADLIB Threads::Threads)
	endif()
endif()

if(WITH_WEBSOCKETS AND WITH_WEBSOCKETS_BUILTIN AND NOT WITH_TLS)
	set(WITH_TLS ON)
	message(WARNING "Re-enabling TLS support because builtin WebSockets is requested. Set WITH_WEBSOCKETS_BUILTIN=OFF to allow WITH_TLS=OFF.")
endif()

if(WITH_TLS)
	find_package(OpenSSL REQUIRED)
	add_definitions("-DWITH_TLS")

	# mosquitto uses OpenSSL 1.1 API, so set OPENSSL_API_COMPAT accordingly:
	# https://www.openssl.org/docs/manmaster/man7/OPENSSL_API_COMPAT.html
	# TODO: migrate off ENGINE API (deprecated since OpenSSL 3.0), see:
	#       https://www.openssl.org/docs/manmaster/man7/migration_guide.html#Engines-and-METHOD-APIs
	add_definitions("-DOPENSSL_API_COMPAT=0x10100000L")

	if (WITH_TLS_PSK)
		add_definitions("-DWITH_TLS_PSK")
	endif (WITH_TLS_PSK)
else()
	set (OPENSSL_INCLUDE_DIR "")
endif()

if(WITH_UNIX_SOCKETS)
	add_definitions("-DWITH_UNIX_SOCKETS")
endif()

# ========================================
# Include projects
# ========================================

option_env(WITH_APPS "Build apps?" ON)
option_env(WITH_BROKER "Build broker?" ON)
option_env(WITH_CLIENTS "Build clients?" ON)
option_env(WITH_DOCS "Build documentation?" ON)
option_env(WITH_PLUGINS "Build plugins?" ON)

target_sources(common-options INTERFACE config.h)
target_include_directories(common-options
	INTERFACE
		${mosquitto_SOURCE_DIR}
		${mosquitto_SOURCE_DIR}/include
)

if(WITH_TLS)
	target_include_directories(common-options
		INTERFACE
			"${OPENSSL_INCLUDE_DIR}"
	)
endif()

if(WITH_BUNDLED_DEPS)
	target_include_directories(common-options
		INTERFACE
			"${mosquitto_SOURCE_DIR}/deps"
	)
endif()

if(WITH_JEMALLOC)
	target_link_libraries(common-options
		INTERFACE
			jemalloc
	)
endif()

add_subdirectory(libcommon)
add_subdirectory(lib)
if(WITH_CLIENTS)
	add_subdirectory(client)
endif()

if(WITH_BROKER)
	add_subdirectory(src)
endif()

if(WITH_APPS)
	add_subdirectory(apps)
endif()

if(WITH_BROKER AND WITH_PLUGINS)
	add_subdirectory(plugins)
endif()

if(WITH_DOCS)
	add_subdirectory(man)
endif()

if(WITH_FUZZING)
	add_subdirectory(fuzzing)
endif()

# ========================================
# Install config file
# ========================================

if(WITH_BROKER)
	custom_install(FILES mosquitto.conf RENAME mosquitto.conf.example DESTINATION "${CMAKE_INSTALL_SYSCONFDIR}/mosquitto")
	custom_install(FILES aclfile.example pskfile.example pwfile.example DESTINATION "${CMAKE_INSTALL_SYSCONFDIR}/mosquitto")
endif()

# ========================================
# Install pkg-config files
# ========================================

configure_file(libmosquitto.pc.in libmosquitto.pc @ONLY)
custom_install(FILES "${CMAKE_CURRENT_BINARY_DIR}/libmosquitto.pc" DESTINATION "${CMAKE_INSTALL_LIBDIR}/pkgconfig")
configure_file(libmosquittopp.pc.in libmosquittopp.pc @ONLY)
custom_install(FILES "${CMAKE_CURRENT_BINARY_DIR}/libmosquittopp.pc" DESTINATION "${CMAKE_INSTALL_LIBDIR}/pkgconfig")

# ========================================
# Install headers
# ========================================
custom_install(
	FILES
	${mosquitto_SOURCE_DIR}/include/mosquitto.h
	${mosquitto_SOURCE_DIR}/include/mosquitto_broker.h
	${mosquitto_SOURCE_DIR}/include/mosquitto_plugin.h
	${mosquitto_SOURCE_DIR}/include/mosquittopp.h
	${mosquitto_SOURCE_DIR}/include/mqtt_protocol.h
	DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
)
custom_install(
	FILES
	${mosquitto_SOURCE_DIR}/include/mosquitto/broker.h
	${mosquitto_SOURCE_DIR}/include/mosquitto/broker_control.h
	${mosquitto_SOURCE_DIR}/include/mosquitto/broker_plugin.h
	${mosquitto_SOURCE_DIR}/include/mosquitto/defs.h
	${mosquitto_SOURCE_DIR}/include/mosquitto/libcommon.h
	${mosquitto_SOURCE_DIR}/include/mosquitto/libcommon_base64.h
	${mosquitto_SOURCE_DIR}/include/mosquitto/libcommon_cjson.h
	${mosquitto_SOURCE_DIR}/include/mosquitto/libcommon_file.h
	${mosquitto_SOURCE_DIR}/include/mosquitto/libcommon_memory.h
	${mosquitto_SOURCE_DIR}/include/mosquitto/libcommon_password.h
	${mosquitto_SOURCE_DIR}/include/mosquitto/libcommon_properties.h
	${mosquitto_SOURCE_DIR}/include/mosquitto/libcommon_random.h
	${mosquitto_SOURCE_DIR}/include/mosquitto/libcommon_string.h
	${mosquitto_SOURCE_DIR}/include/mosquitto/libcommon_time.h
	${mosquitto_SOURCE_DIR}/include/mosquitto/libcommon_topic.h
	${mosquitto_SOURCE_DIR}/include/mosquitto/libcommon_utf8.h
	${mosquitto_SOURCE_DIR}/include/mosquitto/libmosquitto.h
	${mosquitto_SOURCE_DIR}/include/mosquitto/libmosquitto_auth.h
	${mosquitto_SOURCE_DIR}/include/mosquitto/libmosquitto_callbacks.h
	${mosquitto_SOURCE_DIR}/include/mosquitto/libmosquitto_connect.h
	${mosquitto_SOURCE_DIR}/include/mosquitto/libmosquitto_create_delete.h
	${mosquitto_SOURCE_DIR}/include/mosquitto/libmosquitto_helpers.h
	${mosquitto_SOURCE_DIR}/include/mosquitto/libmosquitto_loop.h
	${mosquitto_SOURCE_DIR}/include/mosquitto/libmosquitto_message.h
	${mosquitto_SOURCE_DIR}/include/mosquitto/libmosquitto_options.h
	${mosquitto_SOURCE_DIR}/include/mosquitto/libmosquitto_publish.h
	${mosquitto_SOURCE_DIR}/include/mosquitto/libmosquitto_socks.h
	${mosquitto_SOURCE_DIR}/include/mosquitto/libmosquitto_subscribe.h
	${mosquitto_SOURCE_DIR}/include/mosquitto/libmosquitto_tls.h
	${mosquitto_SOURCE_DIR}/include/mosquitto/libmosquitto_unsubscribe.h
	${mosquitto_SOURCE_DIR}/include/mosquitto/libmosquitto_will.h
	${mosquitto_SOURCE_DIR}/include/mosquitto/libmosquittopp.h
	${mosquitto_SOURCE_DIR}/include/mosquitto/mqtt_protocol.h
	DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/mosquitto"
)

# ========================================
# Testing
# ========================================
if(WITH_TESTS)
	find_package(GTest REQUIRED)
	include(GoogleTest)
	enable_testing()

	function(get_test_files GLOB_LIST EXCLUDE_LIST PY_NAME_LIST)
		set(LOCAL_LIST )
		foreach(PY_TEST_FILE ${${GLOB_LIST}})
			get_filename_component(PY_TEST_NAME ${PY_TEST_FILE} NAME_WE)
			if(${PY_TEST_NAME} IN_LIST EXCLUDE_LIST)
				continue()
			else()
				list(APPEND LOCAL_LIST ${PY_TEST_NAME})
			endif()
		endforeach()
		set(${PY_NAME_LIST} "${LOCAL_LIST}" PARENT_SCOPE)
	endfunction()

    function(mosq_test_set_windows_path name)
        if(WIN32)
            set(PATHMOD
                "PATH=path_list_prepend:$<TARGET_FILE_DIR:libmosquitto_common>"
                "PATH=path_list_prepend:$<TARGET_FILE_DIR:libmosquitto>"
                "PATH=path_list_prepend:${VCPKG_INSTALLED_DIR}/${VCPKG_TARGET_TRIPLET}/bin"
            )
            set_property(TEST ${name}
				PROPERTY
					ENVIRONMENT_MODIFICATION "${PATHMOD}"
			)
        endif()
    endfunction()

	function(mosq_set_test_props name)
		set(fullname "${prefix}-${name}")
		get_property(test_vars GLOBAL PROPERTY TEST_ENV_VARS)
		set_tests_properties("${name}"
			PROPERTIES
				ENVIRONMENT "${test_vars}"
				SKIP_RETURN_CODE 77
		)
		mosq_test_set_windows_path(${name})
	endfunction()

	function(add_python_test PY_TEST_LIST PREFIX PORTS PY_TEST_FILE)
		set(LOCAL_LIST ${${PY_TEST_LIST}})
		get_filename_component(PY_TEST_NAME ${PY_TEST_FILE} NAME_WE)
		if(${PY_TEST_NAME} IN_LIST LOCAL_LIST)
			list(REMOVE_ITEM LOCAL_LIST ${PY_TEST_NAME})
			set(${PY_TEST_LIST} "${LOCAL_LIST}" PARENT_SCOPE)
		else()
			message(SEND_ERROR "Adding non-existent test: ${PY_TEST_FILE}")
		endif()
		add_test(NAME ${PREFIX}${PY_TEST_NAME} COMMAND python3 ${CMAKE_CURRENT_SOURCE_DIR}/${PY_TEST_FILE})
		mosq_set_test_props(${PREFIX}${PY_TEST_NAME})
		if(${PORTS} GREATER 0)
			set(PORT_LIST )
			foreach(X RANGE 1 ${PORTS})
				list(APPEND PORT_LIST "ports:1")
			endforeach()
			list(JOIN PORT_LIST "," PORT_REQ)
			set_tests_properties(${PREFIX}${PY_TEST_NAME}
				PROPERTIES
					RESOURCE_GROUPS "${PORT_REQ}"
			)
		endif()
	endfunction()

	function(check_for_missing_tests PY_TEST_LIST)
		foreach(PY_TEST ${${PY_TEST_LIST}})
			message(SEND_ERROR "Test needs adding: ${PY_TEST}")
		endforeach()
	endfunction()

	if(WITH_PARALLEL_TESTS)
		set(CMAKE_CTEST_ARGUMENTS
			"-j20"
			"--resource-spec-file ../test/resource.json"
			"--output-on-failure"
			"--repeat until-pass:5"
		)
	endif()
	add_subdirectory(test)
endif()
