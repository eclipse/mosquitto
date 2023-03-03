if(WITH_TLS)
	add_executable(mosquitto_passwd
		mosquitto_passwd.c
		get_password.c get_password.h
		../../common/base64_mosq.c ../../common/base64_mosq.h
		../../lib/memory_mosq.c ../../lib/memory_mosq.h
		../../src/memory_public.c
		../../common/misc_mosq.c ../../common/misc_mosq.h
		../../common/password_mosq.c ../../common/password_mosq.h
	)

	target_include_directories(mosquitto_passwd PRIVATE
		"${mosquitto_SOURCE_DIR}"
		"${mosquitto_SOURCE_DIR}/common"
		"${mosquitto_SOURCE_DIR}/include"
		"${mosquitto_SOURCE_DIR}/lib"
		"${mosquitto_SOURCE_DIR}/src"
	)

    target_link_libraries(mosquitto_passwd
	  PRIVATE
	  	common-options
		OpenSSL::SSL
	)

	install(TARGETS mosquitto_passwd
		RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
	)
endif()
