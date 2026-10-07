set(SRC
	mosquitto_signal.c
)

if(WIN32)
	set(SRC ${SRC} signal_windows.c)
else()
	set(SRC ${SRC} signal_unix.c)
endif()

custom_add_executable(mosquitto_signal ${SRC})

target_include_directories(mosquitto_signal PRIVATE
	"${mosquitto_SOURCE_DIR}"
	"${mosquitto_SOURCE_DIR}/include"
	"${mosquitto_SOURCE_DIR}/lib"
	"${mosquitto_SOURCE_DIR}/src"
)

custom_install(TARGETS mosquitto_signal
	RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
)
