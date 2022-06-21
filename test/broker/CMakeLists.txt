add_subdirectory(c)


file(GLOB PY_TEST_FILES [0-9][0-9]-*.py)

list(APPEND PY_TEST_FILES "${CMAKE_CURRENT_SOURCE_DIR}/msg_sequence_test.py")

set(EXCLUDE_LIST
    01-connect-uname-password-success-no-tls
    03-publish-qos1-queued-bytes
    09-extended-auth-single2
    15-persist-client-msg-in-v3-1-1
    15-persist-client-msg-in-v5-0
    15-persist-client-msg-out-queue-v3-1-1
    15-persist-client-msg-out-v3-1-1
    15-persist-client-msg-out-v5-0
    15-persist-client-v3-1-1
    15-persist-client-v5-0
    15-persist-publish-properties-v5-0
    15-persist-retain-v3-1-1
    15-persist-retain-v5-0
    15-persist-subscription-v3-1-1
    15-persist-subscription-v5-0
    # Not a test
    06-bridge-clean-session-core
    08-ssl-bridge-helper
)

foreach(PY_TEST_FILE ${PY_TEST_FILES})
    get_filename_component(PY_TEST_NAME ${PY_TEST_FILE} NAME_WE)
    if(${PY_TEST_NAME} IN_LIST EXCLUDE_LIST)
        continue()
    endif()
    add_test(NAME broker-${PY_TEST_NAME}
        COMMAND ${PY_TEST_FILE}
    )
    set_tests_properties(broker-${PY_TEST_NAME}
        PROPERTIES
            ENVIRONMENT "BUILD_ROOT=${CMAKE_BINARY_DIR}"
    )
endforeach()
