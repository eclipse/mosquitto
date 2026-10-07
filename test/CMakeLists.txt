add_subdirectory(mock)

if(WITH_APPS)
	add_subdirectory(apps)
endif()

if(WITH_BROKER)
	add_subdirectory(broker)
endif()

if(WITH_CLIENTS)
	add_subdirectory(client)
endif()
add_subdirectory(lib)
add_subdirectory(unit)

add_custom_target(coverage
    COMMAND lcov --quiet --capture --directory . --output-file ${PROJECT_BINARY_DIR}/coverage.info --no-external
    COMMAND genhtml --quiet ${PROJECT_BINARY_DIR}/coverage.info --output-directory ${PROJECT_BINARY_DIR}/coverage
    COMMENT "Generating coverage.info and coverage/index.html in ${PROJECT_BINARY_DIR}"
    WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
)
