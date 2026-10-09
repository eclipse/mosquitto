find_package(CUnit REQUIRED)

add_library(common-unit-test-header INTERFACE)
target_include_directories(common-unit-test-header
    INTERFACE
        "${mosquitto_SOURCE_DIR}/include"
        "${mosquitto_SOURCE_DIR}/common"
        "${mosquitto_SOURCE_DIR}/deps"
        "${mosquitto_SOURCE_DIR}/lib"
        "${mosquitto_SOURCE_DIR}/src"
        "${mosquitto_SOURCE_DIR}/test"
)
target_link_libraries(common-unit-test-header
    INTERFACE
        common-options
        cjson
        CUnit::CUnit
)

add_subdirectory(libcommon)
add_subdirectory(broker)
add_subdirectory(lib)
add_subdirectory(dynsec)
