custom_add_executable(mosquitto_db_dump
	db_dump.c db_dump.h
	json.c
	print.c
	stubs.c

	../../common/json_help.c
	../../common/json_help.h

	../../lib/packet_datatypes.c
	../../lib/property_mosq.c

	../../src/persist_read.c
	../../src/persist_read_v234.c
	../../src/persist_read_v5.c
	../../src/topic_tok.c
)

target_compile_definitions(mosquitto_db_dump PRIVATE
	WITH_BROKER
	WITH_PERSISTENCE
)

target_include_directories(mosquitto_db_dump PRIVATE
	"${mosquitto_SOURCE_DIR}/common"
	"${mosquitto_SOURCE_DIR}/lib"
	"${mosquitto_SOURCE_DIR}/libcommon"
	"${mosquitto_SOURCE_DIR}/src"
	"${OPENSSL_INCLUDE_DIR}"
	"${CJSON_INCLUDE_DIRS}"
)

if(WITH_TLS)
	target_link_libraries(mosquitto_db_dump PRIVATE OpenSSL::SSL)
endif()

if(WIN32)
	target_link_libraries(mosquitto_db_dump PRIVATE ws2_32)
endif()

target_link_libraries(mosquitto_db_dump PRIVATE common-options libmosquitto_common)

custom_install(TARGETS mosquitto_db_dump
	RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
)
