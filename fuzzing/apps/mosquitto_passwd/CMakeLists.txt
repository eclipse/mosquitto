function(add_passwd_fuzzer name)
	add_executable(${name} ${name}.cpp)
	target_include_directories(${name} PRIVATE
		${PROJECT_SOURCE_DIR}
		${PROJECT_SOURCE_DIR}/include
		${PROJECT_SOURCE_DIR}/lib
		${PROJECT_SOURCE_DIR}/src
	)
	target_link_libraries(${name} PUBLIC
		fuzzing-common
		libmosquitto_common
		mosquitto_passwd
	)
	install(TARGETS ${name}
		RUNTIME DESTINATION "${OUT}"
	)
endfunction()

add_passwd_fuzzer(mosquitto_passwd_fuzz_load)
