add_subdirectory(c)
add_subdirectory(cpp)


file(GLOB PY_TEST_FILES [0-9][0-9]-*.py)

set(EXCLUDE_LIST
    03-publish-c2b-qos1-timeout
    03-publish-c2b-qos2-timeout
)

foreach(PY_TEST_FILE ${PY_TEST_FILES})
    get_filename_component(PY_TEST_NAME ${PY_TEST_FILE} NAME_WE)
    if(${PY_TEST_NAME} IN_LIST EXCLUDE_LIST)
        continue()
    endif()
    add_test(NAME lib-${PY_TEST_NAME}
        COMMAND ${PY_TEST_FILE} c/${PY_TEST_NAME}.test
    )
    set_tests_properties(lib-${PY_TEST_NAME}
        PROPERTIES
            ENVIRONMENT "BUILD_ROOT=${CMAKE_BINARY_DIR}"
    )
endforeach()
