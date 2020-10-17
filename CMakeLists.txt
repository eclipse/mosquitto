# This is a cmake script. Process it with the CMake gui or command line utility
# to produce makefiles / Visual Studio project files on Mac OS X and Windows.
#
# To configure the build options either use the CMake gui, or run the command
# line utility including the "-i" option.

set(CMAKE_LEGACY_CYGWIN_WIN32 0)

project(mosquitto)

cmake_minimum_required(VERSION 2.8)
# Only for version 3 and up. cmake_policy(SET CMP0042 NEW)

set (VERSION 1.6.12)

add_definitions (-DCMAKE -DVERSION=\"${VERSION}\")

if (WIN32)
	add_definitions("-D_CRT_SECURE_NO_WARNINGS")
	add_definitions("-D_CRT_NONSTDC_NO_DEPRECATE")
endif (WIN32)

include(GNUInstallDirs)

option(WITH_BUNDLED_DEPS "Build with bundled dependencies?" ON)
option(WITH_TLS
	"Include SSL/TLS support?" ON)
option(WITH_TLS_PSK
	"Include TLS-PSK support (requires WITH_TLS)?" ON)
option(WITH_EC
	"Include Elliptic Curve support (requires WITH_TLS)?" ON)
if (WITH_TLS)
	find_package(OpenSSL REQUIRED)
	add_definitions("-DWITH_TLS")

	if (WITH_TLS_PSK)
		add_definitions("-DWITH_TLS_PSK")
	endif (WITH_TLS_PSK)

	if (WITH_EC)
		add_definitions("-DWITH_EC")
	endif (WITH_EC)
else (WITH_TLS)
	set (OPENSSL_INCLUDE_DIR "")
endif (WITH_TLS)

option(WITH_SOCKS "Include SOCKS5 support?" ON)
if (WITH_SOCKS)
	add_definitions("-DWITH_SOCKS")
endif (WITH_SOCKS)

option(WITH_SRV "Include SRV lookup support?" OFF)

option(WITH_STATIC_LIBRARIES "Build static versions of the libmosquitto/pp libraries?" OFF)
option(WITH_PIC "Build the static library with PIC (Position Independent Code) enabled archives?" OFF)

option(WITH_THREADING "Include client library threading support?" ON)
if (WITH_THREADING)
	add_definitions("-DWITH_THREADING")
	if (WIN32)
		if (CMAKE_CL_64)
			set (PTHREAD_LIBRARIES C:\\pthreads\\Pre-built.2\\lib\\x64\\pthreadVC2.lib)
		else (CMAKE_CL_64)
			set (PTHREAD_LIBRARIES C:\\pthreads\\Pre-built.2\\lib\\x86\\pthreadVC2.lib)
		endif (CMAKE_CL_64)
		set (PTHREAD_INCLUDE_DIR C:\\pthreads\\Pre-built.2\\include)
	elseif (ANDROID)
		set (PTHREAD_LIBRARIES "")
		set (PTHREAD_INCLUDE_DIR "")
	else (WIN32)
		find_library(LIBPTHREAD pthread)
		if (LIBPTHREAD)
			set (PTHREAD_LIBRARIES pthread)
		else (LIBPTHREAD)
			set (PTHREAD_LIBRARIES "")
		endif()
		set (PTHREAD_INCLUDE_DIR "")
	endif (WIN32)
else (WITH_THREADING)
	set (PTHREAD_LIBRARIES "")
	set (PTHREAD_INCLUDE_DIR "")
endif (WITH_THREADING)

option(DOCUMENTATION "Build documentation?" ON)

option(WITH_DLT "Include DLT support?" OFF)
message(STATUS "WITH_DLT = ${WITH_DLT}")
if (WITH_DLT)
	#find_package(DLT REQUIRED)
	find_package(PkgConfig)
	pkg_check_modules(DLT "automotive-dlt >= 2.11")
	add_definitions("-DWITH_DLT")
endif (WITH_DLT)

# ========================================
# Include projects
# ========================================

add_subdirectory(lib)
add_subdirectory(client)
add_subdirectory(src)
if (DOCUMENTATION)
	add_subdirectory(man)
endif (DOCUMENTATION)

# ========================================
# Install config file
# ========================================

install(FILES mosquitto.conf aclfile.example pskfile.example pwfile.example DESTINATION "${CMAKE_INSTALL_SYSCONFDIR}/mosquitto")


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
enable_testing()
