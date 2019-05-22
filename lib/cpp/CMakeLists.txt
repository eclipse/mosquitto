include_directories(${mosquitto_SOURCE_DIR}/lib ${mosquitto_SOURCE_DIR}/lib/cpp
			${STDBOOL_H_PATH} ${STDINT_H_PATH})
link_directories(${mosquitto_BINARY_DIR}/lib)

set(CPP_SRC mosquittopp.cpp mosquittopp.h)

add_library(mosquittopp SHARED ${CPP_SRC})
set_target_properties(mosquittopp PROPERTIES
	POSITION_INDEPENDENT_CODE 1
	PUBLIC_HEADER ${CMAKE_CURRENT_SOURCE_DIR}/mosquittopp.h
	VERSION ${PROJECT_VERSION}
	SOVERSION 1
)

target_include_directories(
	mosquittopp
	INTERFACE
	$<BUILD_INTERFACE:${MOSQUITTO_INCLUDE_BUILD_DIR}>
	$<INSTALL_INTERFACE:include>
)

target_link_libraries(mosquittopp libmosquitto)

install(TARGETS mosquittopp EXPORT ${MOSQUITTO_TARGETS_EXPORT_NAME} LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}" PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

if (WITH_STATIC_LIBRARIES)
	add_library(mosquittopp_static STATIC
		${C_SRC}
		${CPP_SRC}
	)
	if (WITH_PIC)
		set_target_properties(mosquittopp_static PROPERTIES
			POSITION_INDEPENDENT_CODE 1
		)
	endif (WITH_PIC)

	target_link_libraries(mosquittopp_static ${LIBRARIES})

	set_target_properties(mosquittopp_static PROPERTIES
		PUBLIC_HEADER ${CMAKE_CURRENT_SOURCE_DIR}/mosquittopp.h
		OUTPUT_NAME mosquittopp
		VERSION ${PROJECT_VERSION}
	)

	target_include_directories(
		mosquittopp_static
		INTERFACE
		$<BUILD_INTERFACE:${MOSQUITTO_INCLUDE_BUILD_DIR}>
		$<INSTALL_INTERFACE:include>
	)

	target_compile_definitions(mosquittopp_static PUBLIC "LIBMOSQUITTO_STATIC")

	install(TARGETS mosquittopp_static EXPORT ${MOSQUITTO_TARGETS_EXPORT_NAME} ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}" PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
endif (WITH_STATIC_LIBRARIES)
