# This is a cmake script. Process it with the CMake gui or command line utility
# to produce makefiles / Visual Studio project files on Mac OS X and Windows.
#
# To configure the build options either use the CMake gui, or run the command
# line utility including the "-i" option.

set(CMAKE_LEGACY_CYGWIN_WIN32 0)

project(mosquitto)

cmake_minimum_required(VERSION 2.8)
# Only for version 3 and up. cmake_policy(SET CMP0042 NEW)

set (VERSION 1.4.90)

if (WIN32)
	set (BINDIR .)
	set (SBINDIR .)
	set (SYSCONFDIR .)
	set (LIBDIR .)
	set (INCLUDEDIR include)
	set (DATAROOTDIR share)
	set (MANDIR man)
	set (SHAREDEST .)
	set (PKGCONFIGDIR "${LIBDIR}/pkgconfig")
	add_definitions("-D_CRT_SECURE_NO_WARNINGS")
	add_definitions("-D_CRT_NONSTDC_NO_DEPRECATE")
else (WIN32)
	set (BINDIR bin)
	set (SBINDIR sbin)
	if ("${CMAKE_INSTALL_PREFIX}" STREQUAL /usr)
		set (SYSCONFDIR /etc/mosquitto)
	else ("${CMAKE_INSTALL_PREFIX}" STREQUAL /usr)
		set (SYSCONFDIR etc/mosquitto)
	endif ("${CMAKE_INSTALL_PREFIX}" STREQUAL /usr)

	set (LIBDIR lib${LIB_SUFFIX})
	set (CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_PREFIX}/${LIBDIR}")
	set (INCLUDEDIR include)
	set (DATAROOTDIR share)
	set (MANDIR "${DATAROOTDIR}/man")
	set (SHAREDIR "${DATAROOTDIR}/mosquitto")
	set (PKGCONFIGDIR "${LIBDIR}/pkgconfig")
endif (WIN32)

option(WITH_TLS
	"Include SSL/TLS support?" ON)
option(WITH_TLS_PSK
	"Include TLS-PSK support (requires WITH_TLS)?" ON)
option(WITH_EC
	"Include Elliptic Curve support (requires WITH_TLS)?" ON)
option(WITH_SOCKS "Include SOCKS5 support?" ON)

option(WITH_SRV "Include SRV lookup support?" OFF)

option(DOCUMENTATION "Build documentation?" ON)

option(WITH_STATIC_LIBRARIES "Build static versions of the libmosquitto/pp libraries?" OFF)
option(WITH_PIC "Build the static library with PIC (Position Independent Code) enabled archives?" OFF)
option(WITH_THREADING "Include client library threading support?" ON)

# ========================================
# Include projects
# ========================================

add_subdirectory(lib)
add_subdirectory(client)
add_subdirectory(src)
if (${DOCUMENTATION} STREQUAL ON)
	add_subdirectory(man)
endif (${DOCUMENTATION} STREQUAL ON)

# ========================================
# Install config file
# ========================================

install(FILES mosquitto.conf aclfile.example pskfile.example pwfile.example DESTINATION "${SYSCONFDIR}")


# ========================================
# Install pkg-config files
# ========================================

configure_file(libmosquitto.pc.in libmosquitto.pc @ONLY)
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/libmosquitto.pc" DESTINATION "${PKGCONFIGDIR}")
configure_file(libmosquittopp.pc.in libmosquittopp.pc @ONLY)
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/libmosquittopp.pc" DESTINATION "${PKGCONFIGDIR}")

# ========================================
# Testing
# ========================================
add_custom_target(Tests COMMAND make -C ${mosquitto_SOURCE_DIR}/test test)
