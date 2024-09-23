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

if(WIN32)
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
		"${mosquitto_SOURCE_DIR}/"
		"${mosquitto_SOURCE_DIR}/include"
)

target_link_libraries(libmosquitto_common
	PUBLIC
		config-header
		cJSON
)

if(ARGON2_FOUND)
	target_link_libraries(libmosquitto_common PRIVATE argon2)
endif()

if (WITH_TLS)
	target_link_libraries(libmosquitto_common
		PUBLIC
			OpenSSL::SSL
	)
endif()

if(INC_MEMTRACK)
	target_compile_definitions(libmosquitto_common PUBLIC "WITH_MEMORY_TRACKING")
endif()

option(ALLOC_MISMATCH_INVALID_READ "Memory function mismatch detection." OFF)
if(ALLOC_MISMATCH_INVALID_READ)
	target_compile_definitions(libmosquitto_common PRIVATE "ALLOC_MISMATCH_INVALID_READ")
endif()

option(ALLOC_MISMATCH_ABORT "Memory function mismatch abort." OFF)
if(ALLOC_MISMATCH_ABORT)
	target_compile_definitions(libmosquitto_common PRIVATE "ALLOC_MISMATCH_ABORT")
endif()

set_target_properties(libmosquitto_common PROPERTIES
	OUTPUT_NAME mosquitto_common
	VERSION ${VERSION}
	SOVERSION 1
	POSITION_INDEPENDENT_CODE 1
)
