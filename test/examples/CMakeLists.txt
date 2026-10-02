add_executable(temperature_conversion_test
	temperature_conversion_test.cpp
	${mosquitto_SOURCE_DIR}/examples/temperature_conversion/temperature_conversion.cpp
	${mosquitto_SOURCE_DIR}/lib/cpp/mosquittopp.cpp
	$<TARGET_OBJECTS:libmosquitto_mock>
)
target_include_directories(temperature_conversion_test PRIVATE
	${mosquitto_SOURCE_DIR}/examples/temperature_conversion
	${mosquitto_SOURCE_DIR}/include
	${mosquitto_SOURCE_DIR}/lib
	${mosquitto_SOURCE_DIR}/test/mock
	${mosquitto_SOURCE_DIR}/test/mock/lib
)
target_link_libraries(temperature_conversion_test PRIVATE
	GTest::gmock_main
	cJSON
	libmosquitto_common
)
gtest_discover_tests(temperature_conversion_test)
