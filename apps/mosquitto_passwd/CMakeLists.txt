include_directories(${mosquitto_SOURCE_DIR} ${mosquitto_SOURCE_DIR}/include
		${mosquitto_SOURCE_DIR}/lib ${mosquitto_SOURCE_DIR}/src
		${OPENSSL_INCLUDE_DIR} ${STDBOOL_H_PATH} ${STDINT_H_PATH})

if (WITH_TLS)
	add_executable(mosquitto_passwd
		mosquitto_passwd.c
		get_password.c get_password.h
		../../lib/memory_mosq.c ../../lib/memory_mosq.h
		../../src/memory_public.c
		../../lib/misc_mosq.c
		../../src/password_mosq.c ../../src/password_mosq.h
		)


	target_link_libraries(mosquitto_passwd ${OPENSSL_LIBRARIES})
	install(TARGETS mosquitto_passwd RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}")
endif (WITH_TLS)
