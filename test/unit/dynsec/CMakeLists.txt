add_executable(dynsec-utils-test
    utils_test.cpp
    ${CMAKE_SOURCE_DIR}/plugins/dynamic-security/utils.c
)
target_include_directories(dynsec-utils-test PRIVATE
    ${mosquitto_SOURCE_DIR}/plugins/dynamic-security
    ${mosquitto_SOURCE_DIR}/include
    ${mosquitto_SOURCE_DIR}/deps
)
target_link_libraries(dynsec-utils-test PRIVATE
    GTest::gtest_main
)
gtest_discover_tests(dynsec-utils-test)

