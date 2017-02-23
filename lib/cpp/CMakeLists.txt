include_directories(${mosquitto_SOURCE_DIR}/lib ${mosquitto_SOURCE_DIR}/lib/cpp
			${STDBOOL_H_PATH} ${STDINT_H_PATH})
link_directories(${mosquitto_BINARY_DIR}/lib)

set (SOURCE_LIB_CPP mosquittopp.cpp mosquittopp.h)

if (${STATIC_LIB} STREQUAL ON)
	add_library(mosquittopp STATIC ${SOURCE_LIB_CPP})
else (${STATIC_LIB} STREQUAL ON)
	add_library(mosquittopp SHARED ${SOURCE_LIB_CPP})
endif (${STATIC_LIB} STREQUAL ON)

target_link_libraries(mosquittopp libmosquitto)
set_target_properties(mosquittopp PROPERTIES
	VERSION ${VERSION}
	SOVERSION 1
)
install(TARGETS mosquittopp RUNTIME DESTINATION "${BINDIR}" LIBRARY DESTINATION "${LIBDIR}" ARCHIVE DESTINATION "${LIBDIR}")
install(FILES mosquittopp.h DESTINATION "${INCLUDEDIR}")

if (UNIX)
	install(CODE "EXEC_PROGRAM(/sbin/ldconfig)")
endif (UNIX)
