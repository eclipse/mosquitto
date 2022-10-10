set(CPP_SRC mosquittopp.cpp ../../include/mosquittopp.h)

add_library(mosquittopp SHARED
	${CPP_SRC}
)

set_target_properties(mosquittopp PROPERTIES
	POSITION_INDEPENDENT_CODE 1
)

target_include_directories(mosquittopp
	PUBLIC
		"${mosquitto_SOURCE_DIR}/include"
)

target_link_libraries(mosquittopp
	PUBLIC libmosquitto
	PRIVATE common-options
)

if (WITH_THREADING AND NOT WIN32)
	set(THREADS_PREFER_PTHREAD_FLAG ON)
	find_package(Threads REQUIRED)

	target_link_libraries(mosquittopp PRIVATE Threads::Threads)
endif()

set_target_properties(mosquittopp PROPERTIES
	VERSION ${VERSION}
	SOVERSION 1
)
install(TARGETS mosquittopp
	RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
	ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
	LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
)

if(WITH_STATIC_LIBRARIES)
	add_library(mosquittopp_static STATIC
		${C_SRC}
		${CPP_SRC}
	)
	if(WITH_PIC)
		set_target_properties(mosquittopp_static PROPERTIES
			POSITION_INDEPENDENT_CODE 1
		)
	endif()

	target_include_directories(mosquittopp_static PRIVATE
		"${mosquitto_SOURCE_DIR}/include"
		"${mosquitto_SOURCE_DIR}/lib"
		"${mosquitto_SOURCE_DIR}/lib/cpp"
	)

	target_link_libraries(mosquittopp_static PRIVATE ${LIBRARIES})

	set_target_properties(mosquittopp_static PROPERTIES
		OUTPUT_NAME mosquittopp_static
		VERSION ${VERSION}
	)

	target_compile_definitions(mosquittopp_static PUBLIC "LIBMOSQUITTO_STATIC")
	install(TARGETS mosquittopp_static
		ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
	)
endif()

install(FILES ${mosquitto_SOURCE_DIR}/include/mosquittopp.h DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}")
