set(C_SRC
	base64_common.c
	file_common.c
	memory_common.c
	mqtt_common.c
	property_common.c
	random_common.c
	strings_common.c
	time_common.c
	topic_common.c
	utf8_common.c
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
)

if (WITH_TLS)
	target_link_libraries(libmosquitto_common
		PUBLIC
			OpenSSL::SSL
	)
endif()


set_target_properties(libmosquitto_common PROPERTIES
	OUTPUT_NAME mosquitto_common
	VERSION ${VERSION}
	SOVERSION 1
	POSITION_INDEPENDENT_CODE 1
)
