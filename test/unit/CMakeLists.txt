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
        config-header
        CUnit::CUnit
)

# unit-broker
add_executable(broker-test
    datatype_read.c
    datatype_write.c
    misc_trim_test.c
    property_add.c
    property_read.c
    property_user_read.c
    property_write.c
    stubs.c
    util_topic_test.c
    utf8.c
    # main test files
    test.c
    ../../lib/packet_datatypes.c
    ../../lib/packet_mosq.c
    ../../lib/property_mosq.c
    ../../lib/memory_mosq.c
    ../../common/misc_mosq.c
    ../../lib/util_mosq.c
    ../../lib/util_topic.c
    ../../lib/utf8_mosq.c
)

target_link_libraries(broker-test PRIVATE common-unit-test-header OpenSSL::SSL)
add_test(NAME unit-broker-test COMMAND broker-test)

# bridge-topic-test
add_library(bridge-topic-obj OBJECT ../../src/bridge_topic.c)
target_compile_definitions(bridge-topic-obj PRIVATE WITH_BRIDGE WITH_BROKER)
target_link_libraries(bridge-topic-obj PUBLIC common-unit-test-header)

add_executable(bridge-topic-test
    bridge_topic_test.c
    stubs.c
    ../../lib/memory_mosq.c
    ../../src/memory_public.c
    ../../lib/util_topic.c
)
target_link_libraries(bridge-topic-test PRIVATE bridge-topic-obj common-unit-test-header)
add_test(NAME unit-bridge-topic-test COMMAND bridge-topic-test)

# keepalive-test
add_executable(keepalive-test
    keepalive_test.c
    keepalive_stubs.c
    ../../lib/memory_mosq.c
)
target_link_libraries(keepalive-test PRIVATE common-unit-test-header)
add_test(NAME unit-keepalive-test COMMAND keepalive-test)

# persist-read-test
add_library(persistence-read-obj
    OBJECT
        ../../src/persist_read_v234.c
        ../../src/persist_read_v5.c
        ../../src/persist_read.c
        ../../src/retain.c
        ../../src/topic_tok.c
)
target_compile_definitions(persistence-read-obj PRIVATE WITH_PERSISTENCE WITH_BROKER)
target_link_libraries(persistence-read-obj PUBLIC common-unit-test-header OpenSSL::SSL)

add_executable(persist-read-test
    persist_read_test.c
    persist_read_stubs.c
    ../../common/misc_mosq.c
    ../../lib/memory_mosq.c
    ../../lib/packet_datatypes.c
    ../../lib/property_mosq.c
    ../../lib/utf8_mosq.c
    ../../lib/util_mosq.c
    ../../src/memory_public.c
)
target_compile_definitions(persist-read-test PRIVATE TEST_SOURCE_DIR="${CMAKE_CURRENT_SOURCE_DIR}")
target_link_libraries(persist-read-test PRIVATE persistence-read-obj)
add_test(NAME unit-persist-read-test COMMAND persist-read-test)

# persist-write-test
add_library(persistence-write-obj
    OBJECT
        ../../src/database.c
        ../../src/persist_read_v234.c
        ../../src/persist_read_v5.c
        ../../src/persist_read.c
        ../../src/persist_write_v5.c
        ../../src/persist_write.c
        ../../src/retain.c
        ../../src/subs.c
        ../../src/topic_tok.c
)
target_compile_definitions(persistence-write-obj PRIVATE WITH_PERSISTENCE WITH_BROKER)
target_link_libraries(persistence-write-obj PUBLIC common-unit-test-header)

add_executable(persist-write-test
    persist_write_test.c
    persist_write_stubs.c
    ../../common/misc_mosq.c
    ../../lib/memory_mosq.c
    ../../lib/packet_datatypes.c
    ../../lib/property_mosq.c
    ../../lib/utf8_mosq.c
    ../../lib/util_mosq.c
    ../../src/memory_public.c
    ../../lib/packet_mosq.c
)
target_compile_definitions(persist-write-test PRIVATE TEST_SOURCE_DIR="${CMAKE_CURRENT_SOURCE_DIR}")
target_link_libraries(persist-write-test PRIVATE persistence-write-obj OpenSSL::SSL)
add_test(NAME unit-persist-write-test COMMAND persist-write-test)

# subs-test
add_library(persistence-obj
    OBJECT
        ../../src/database.c
        ../../src/subs.c
        ../../src/topic_tok.c
)
target_compile_definitions(persistence-obj PRIVATE WITH_PERSISTENCE WITH_BROKER)
target_link_libraries(persistence-obj PUBLIC common-unit-test-header)

add_executable(subs-test
    subs_stubs.c
    subs_test.c
    ../../lib/memory_mosq.c
    ../../src/memory_public.c
)

target_link_libraries(subs-test PRIVATE common-unit-test-header persistence-obj)
add_test(NAME unit-subs-test COMMAND subs-test)
