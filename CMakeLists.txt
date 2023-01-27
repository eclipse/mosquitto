# This is a cmake script. Process it with the CMake gui or command line utility
# to produce makefiles / Visual Studio project files on Mac OS X and Windows.
#
# To configure the build options either use the CMake gui, or run the command
# line utility including the "-i" option.

cmake_minimum_required(VERSION 3.14)

set (VERSION 2.1.0)
project(mosquitto
	VERSION ${VERSION}
	DESCRIPTION "Eclipse Mosquitto"
	LANGUAGES C CXX
)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

list(APPEND CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake/")

add_definitions (-DCMAKE -DVERSION=\"${VERSION}\")

if(WIN32)
	add_definitions("-D_CRT_SECURE_NO_WARNINGS")
	add_definitions("-D_CRT_NONSTDC_NO_DEPRECATE")
endif()

if(APPLE)
	set(CMAKE_SHARED_LIBRARY_CREATE_C_FLAGS "${CMAKE_SHARED_LIBRARY_CREATE_C_FLAGS} -undefined dynamic_lookup")
endif()

add_library(common-options INTERFACE)
if(NOT WIN32)
	target_compile_options(common-options INTERFACE -Wall -Wextra -Wconversion)
endif()

include(GNUInstallDirs)
include(CheckIncludeFiles)

option(WITH_BUNDLED_DEPS "Build with bundled dependencies?" ON)
option(WITH_TLS "Include SSL/TLS support?" ON)
option(WITH_TLS_PSK "Include TLS-PSK support (requires WITH_TLS)?" ON)
option(WITH_EC "Include Elliptic Curve support (requires WITH_TLS)?" ON)
option(WITH_TESTS "Enable tests" ON)
if (WITH_TLS)
	find_package(OpenSSL REQUIRED)
	add_definitions("-DWITH_TLS")

	if (WITH_TLS_PSK)
		add_definitions("-DWITH_TLS_PSK")
	endif (WITH_TLS_PSK)

	if (WITH_EC)
		add_definitions("-DWITH_EC")
	endif (WITH_EC)
else()
	set (OPENSSL_INCLUDE_DIR "")
endif()

option(WITH_SQLITE "Include sqlite persistence support?" ON)
if (WITH_SQLITE)
	find_package(SQLite3 REQUIRED)
	add_definitions("-DWITH_SQLITE")
endif()

option(WITH_YAML "Include yaml configuration file support?" ON)
if (WITH_SQLITE)
	find_package(Yaml REQUIRED)
	add_definitions("-DWITH_YAML")
endif()


option(WITH_UNIX_SOCKETS "Include Unix Domain Socket support?" ON)
if(WITH_UNIX_SOCKETS AND NOT WIN32)
	add_definitions("-DWITH_UNIX_SOCKETS")
endif()

option(WITH_SOCKS "Include SOCKS5 support?" ON)
if(WITH_SOCKS)
	add_definitions("-DWITH_SOCKS")
endif()

option(WITH_WEBSOCKETS "Include websockets support?" ON)
option(WITH_WEBSOCKETS_BUILTIN "Websockets support uses builtin library? Set OFF to use libwebsockets" ON)

option(WITH_SRV "Include SRV lookup support?" OFF)
option(WITH_STATIC_LIBRARIES "Build static versions of the libmosquitto/pp libraries?" OFF)
option(WITH_PIC "Build the static library with PIC (Position Independent Code) enabled archives?" OFF)

option(WITH_THREADING "Include threading support?" ON)
if(WITH_THREADING)
	add_definitions("-DWITH_THREADING")
endif()

option(WITH_DLT "Include DLT support?" OFF)
message(STATUS "WITH_DLT = ${WITH_DLT}")
if(WITH_DLT)
	find_package(PkgConfig)
	pkg_check_modules(DLT "automotive-dlt >= 2.11" REQUIRED)
endif()

option(WITH_CJSON "Build with cJSON support (required for dynamic security plugin and useful for mosquitto_sub)?" ON)
if(WITH_CJSON)
	FIND_PACKAGE(cJSON)
	if(CJSON_FOUND)
		target_compile_definitions(cJSON INTERFACE WITH_CJSON)
	else()
		message(STATUS "Optional dependency cJSON not found. Some features will be disabled.")
	endif()
endif()

option(WITH_LTO "Build with link time optimizations (IPO) / interprocedural optimization (IPO) enabled." ON)
if(WITH_LTO)
	include(CheckIPOSupported)
	check_ipo_supported(RESULT is_ipo_supported OUTPUT output)
	if(is_ipo_supported)
		set_property(TARGET common-options PROPERTY INTERPROCEDURAL_OPTIMIZATION TRUE)
	else()
		message(WARNING "LTO/IPO is not supported: ${output}")
	endif()
endif()

# ========================================
# Include projects
# ========================================

option(WITH_CLIENTS "Build clients?" ON)
option(WITH_BROKER "Build broker?" ON)
option(WITH_APPS "Build apps?" ON)
option(WITH_PLUGINS "Build plugins?" ON)
option(DOCUMENTATION "Build documentation?" ON)

add_library(config-header INTERFACE)
target_sources(config-header INTERFACE config.h)
target_include_directories(config-header
	INTERFACE
		${mosquitto_SOURCE_DIR}
)

if(WITH_TLS)
	target_include_directories(config-header
		INTERFACE
			"${OPENSSL_INCLUDE_DIR}"
	)
endif()


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

if(WITH_PLUGINS)
	add_subdirectory(plugins)
endif()

if(DOCUMENTATION)
	add_subdirectory(man)
endif()

# ========================================
# Install config file
# ========================================

if(WITH_BROKER)
	install(FILES mosquitto.conf aclfile.example pskfile.example pwfile.example DESTINATION "${CMAKE_INSTALL_SYSCONFDIR}/mosquitto")
endif()

# ========================================
# Install pkg-config files
# ========================================

configure_file(libmosquitto.pc.in libmosquitto.pc @ONLY)
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/libmosquitto.pc" DESTINATION "${CMAKE_INSTALL_LIBDIR}/pkgconfig")
configure_file(libmosquittopp.pc.in libmosquittopp.pc @ONLY)
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/libmosquittopp.pc" DESTINATION "${CMAKE_INSTALL_LIBDIR}/pkgconfig")

# ========================================
# Testing
# ========================================
if(WITH_TESTS)
	enable_testing()
	add_subdirectory(test)
endif()
