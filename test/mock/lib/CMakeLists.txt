add_library(libmosquitto_mock OBJECT
	actions_publish_mock.cpp
	actions_subscribe_mock.cpp
	actions_unsubscribe_mock.cpp
	callbacks_mock.cpp
	connect_mock.cpp
	extended_auth_mock.cpp
	helpers_mock.cpp
	libmosquitto_mock.cpp
	libmosquitto_mock.hpp
	loop_mock.cpp
	messages_mosq_mock.cpp
	net_mosq_mock.cpp
	options_mock.cpp
	socks_mosq_mock.cpp
	srv_mosq_mock.cpp
	thread_mosq_mock.cpp
)

target_include_directories(libmosquitto_mock
    PUBLIC
        ${mosquitto_SOURCE_DIR}
        ${mosquitto_SOURCE_DIR}/include
        ${mosquitto_SOURCE_DIR}/lib
        ${mosquitto_SOURCE_DIR}/test/mock
        ${mosquitto_SOURCE_DIR}/test/mock/lib
)
target_link_libraries(libmosquitto_mock PRIVATE cjson GTest::gmock)
