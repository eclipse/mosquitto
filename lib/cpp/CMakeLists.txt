add_library(mosquittopp SHARED mosquittopp.cpp)

target_include_directories(mosquittopp PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
target_link_libraries(mosquittopp PRIVATE libmosquitto)

set_target_properties(mosquittopp PROPERTIES
	OUTPUT_NAME mosquittopp
	VERSION ${VERSION}
)

if (${WITH_STATIC_LIBRARIES} STREQUAL ON)
	target_compile_definitions(mosquittopp PUBLIC LIBMOSQUITTO_STATIC)

	if (${WITH_PIC} STREQUAL ON)
		set_target_properties(mosquittopp PROPERTIES POSITION_INDEPENDENT_CODE 1)
	endif (${WITH_PIC} STREQUAL ON)
else (${WITH_STATIC_LIBRARIES} STREQUAL ON)
	set_target_properties(mosquittopp PROPERTIES SOVERSION 1)
endif (${WITH_STATIC_LIBRARIES} STREQUAL ON)

install(TARGETS mosquittopp
	RUNTIME DESTINATION "${BINDIR}"
	ARCHIVE DESTINATION "${LIBDIR}"
	LIBRARY DESTINATION "${LIBDIR}"
)
install(FILES mosquittopp.h DESTINATION "${INCLUDEDIR}")

if (UNIX AND NOT APPLE)
	install(CODE "EXEC_PROGRAM(/sbin/ldconfig)")
endif (UNIX AND NOT APPLE)
