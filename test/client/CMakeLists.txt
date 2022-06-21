file(GLOB PY_TEST_FILES [0-9][0-9]-*.py)

set(EXCLUDE_LIST
    # none
)

foreach(PY_TEST_FILE ${PY_TEST_FILES})
    get_filename_component(PY_TEST_NAME ${PY_TEST_FILE} NAME_WE)
    if(${PY_TEST_NAME} IN_LIST EXCLUDE_LIST)
        continue()
    endif()
    add_test(NAME client-${PY_TEST_NAME}
        COMMAND ${PY_TEST_FILE}
    )
    set_tests_properties(client-${PY_TEST_NAME}
        PROPERTIES
            ENVIRONMENT "BUILD_ROOT=${CMAKE_BINARY_DIR}"
    )
endforeach()
