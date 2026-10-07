add_library(libmosquitto_common_mock OBJECT
	libmosquitto_common_mock.hpp
	libmosquitto_common_mock.cpp
	base64_common_mock.cpp
	file_common_mock.cpp
	memory_common_mock.cpp
	mqtt_common_mock.cpp
	password_common_mock.cpp
	property_common_mock.cpp
	random_common_mock.cpp
	strings_common_mock.cpp
	time_common_mock.cpp
	topic_common_mock.cpp
	utf8_common_mock.cpp
)

target_include_directories(libmosquitto_common_mock
    PUBLIC
        ${mosquitto_SOURCE_DIR}
        ${mosquitto_SOURCE_DIR}/include
        ${mosquitto_SOURCE_DIR}/lib
        ${mosquitto_SOURCE_DIR}/test/mock
        ${mosquitto_SOURCE_DIR}/test/mock/lib
)
target_link_libraries(libmosquitto_common_mock PRIVATE cjson GTest::gmock)
