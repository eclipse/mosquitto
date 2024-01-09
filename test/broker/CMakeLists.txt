add_subdirectory(c)

file(GLOB PY_TEST_FILES [0-9][0-9]-*.py)
file(GLOB PY_PERSIST_TEST_FILES 15-*.py)

list(APPEND PY_TEST_FILES "${CMAKE_CURRENT_SOURCE_DIR}/msg_sequence_test.py")

set(PERSIST_LIST
    persist_sqlite
)
set(PERSIST_LMDB_EXCLUDE_LIST
    15-persist-migrate-db
    15-persist-migrate-db
)

set(EXCLUDE_LIST
    01-connect-uname-password-success-no-tls
    03-publish-qos1-queued-bytes
    09-extended-auth-single2
    # Not a test
    06-bridge-clean-session-core
    08-ssl-bridge-helper
)

foreach(PY_PERSIST_TEST_FILE ${PY_PERSIST_TEST_FILES})
    get_filename_component(PY_PERSIST_TEST_NAME ${PY_PERSIST_TEST_FILE} NAME_WE)
    list(APPEND EXCLUDE_LIST ${PY_PERSIST_TEST_NAME})
endforeach()

foreach(PY_TEST_FILE ${PY_TEST_FILES})
    get_filename_component(PY_TEST_NAME ${PY_TEST_FILE} NAME_WE)
    if(${PY_TEST_NAME} IN_LIST EXCLUDE_LIST OR ${PY_TEST_NAME} IN_LIST SQLITE_LIST)
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

foreach(PERSIST_TYPE ${PERSIST_LIST})
    foreach(PY_TEST_FILE ${PY_PERSIST_TEST_FILES})
        get_filename_component(PY_TEST_NAME ${PY_TEST_FILE} NAME_WE)
        if("${PERSIST_TYPE}" STREQUAL "persist_lmdb" AND ${PY_TEST_NAME} IN_LIST PERSIST_LMDB_EXCLUDE_LIST)
	    continue()
	endif()
        add_test(NAME broker-${PY_TEST_NAME}-${PERSIST_TYPE}
            COMMAND ${PY_TEST_FILE} ${PERSIST_TYPE}
        )
        set_tests_properties(broker-${PY_TEST_NAME}-${PERSIST_TYPE}
            PROPERTIES
                ENVIRONMENT "BUILD_ROOT=${CMAKE_BINARY_DIR}"
        )
    endforeach()
endforeach()
