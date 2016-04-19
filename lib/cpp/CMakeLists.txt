include_directories(${mosquitto_SOURCE_DIR}/lib ${mosquitto_SOURCE_DIR}/lib/cpp
			${STDBOOL_H_PATH} ${STDINT_H_PATH})
link_directories(${mosquitto_BINARY_DIR}/lib)

add_library(mosquittopp SHARED
	mosquittopp.cpp mosquittopp.h)

target_link_libraries(mosquittopp libmosquitto)
set_target_properties(mosquittopp PROPERTIES
	VERSION ${VERSION}
	SOVERSION 1
)
install(TARGETS mosquittopp RUNTIME DESTINATION ${BINDIR} LIBRARY DESTINATION ${LIBDIR})
install(FILES mosquittopp.h DESTINATION ${INCLUDEDIR})

if (UNIX AND NOT APPLE)
	install(CODE "EXEC_PROGRAM(/sbin/ldconfig)")
endif (UNIX AND NOT APPLE)

