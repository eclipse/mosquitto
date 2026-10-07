set(C_SRC
	base64_common.c
	cjson_common.c
	file_common.c
	memory_common.c
	mqtt_common.c
	password_common.c
	property_common.c
	random_common.c
	strings_common.c
	time_common.c
	topic_common.c
	utf8_common.c

	"${mosquitto_SOURCE_DIR}/include/mosquitto/libcommon.h"
	"${mosquitto_SOURCE_DIR}/include/mosquitto/libcommon_base64.h"
	"${mosquitto_SOURCE_DIR}/include/mosquitto/libcommon_cjson.h"
	"${mosquitto_SOURCE_DIR}/include/mosquitto/libcommon_file.h"
	"${mosquitto_SOURCE_DIR}/include/mosquitto/libcommon_memory.h"
	"${mosquitto_SOURCE_DIR}/include/mosquitto/libcommon_properties.h"
	"${mosquitto_SOURCE_DIR}/include/mosquitto/libcommon_random.h"
	"${mosquitto_SOURCE_DIR}/include/mosquitto/libcommon_string.h"
	"${mosquitto_SOURCE_DIR}/include/mosquitto/libcommon_time.h"
	"${mosquitto_SOURCE_DIR}/include/mosquitto/libcommon_topic.h"
	"${mosquitto_SOURCE_DIR}/include/mosquitto/libcommon_utf8.h"
)

option_env(ALLOC_MISMATCH_INVALID_READ "Memory function mismatch detection." OFF)
option_env(ALLOC_MISMATCH_ABORT "Memory function mismatch abort." OFF)

if(WIN32)
	set(WITH_SHARED_LIBCOMMON_DEF ON)
else()
	set(WITH_SHARED_LIBCOMMON_DEF OFF)
endif()
option_env(WITH_SHARED_LIBCOMMON "Build libmosquitto_common as a shared library?" ${WITH_SHARED_LIBCOMMON_DEF})

if(WITH_SHARED_LIBCOMMON)
	add_library(libmosquitto_common SHARED
		${C_SRC}
	)
else()
	add_library(libmosquitto_common OBJECT
		${C_SRC}
	)
endif()

target_include_directories(libmosquitto_common
	PUBLIC
		"${CJSON_INCLUDE_DIRS}"
)

target_link_libraries(libmosquitto_common
	PUBLIC
		common-options
		cjson
)

if(ARGON2_FOUND)
	target_link_libraries(libmosquitto_common PRIVATE argon2)
endif()

if(ALLOC_MISMATCH_INVALID_READ)
	target_compile_definitions(libmosquitto_common PRIVATE "ALLOC_MISMATCH_INVALID_READ")
endif()

if(ALLOC_MISMATCH_ABORT)
	target_compile_definitions(libmosquitto_common PRIVATE "ALLOC_MISMATCH_ABORT")
endif()

if(INC_MEMTRACK)
	target_compile_definitions(libmosquitto_common PUBLIC "WITH_MEMORY_TRACKING")
endif()

if(WITH_TLS)
	target_link_libraries(libmosquitto_common
		PUBLIC
			OpenSSL::SSL
	)
elseif(NOT WIN32)
	include(CheckSymbolExists)
	check_symbol_exists(getrandom "sys/random.h" GETRANDOM_FOUND)
	if(GETRANDOM_FOUND)
		add_definitions("-DHAVE_GETRANDOM")
	else()
		message(FATAL_ERROR "C library does not provide getrandom(); enable WITH_TLS instead")
	endif()
endif()

set_target_properties(libmosquitto_common PROPERTIES
	OUTPUT_NAME mosquitto_common
	VERSION ${VERSION}
	SOVERSION 1
	POSITION_INDEPENDENT_CODE 1
)

custom_install(TARGETS libmosquitto_common
	RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
	ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
	LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
)
