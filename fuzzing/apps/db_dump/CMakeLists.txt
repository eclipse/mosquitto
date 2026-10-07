function(add_db_dump_fuzzer name)
	add_executable(${name} ${name}.cpp)
	target_include_directories(${name} PRIVATE
		${PROJECT_SOURCE_DIR}
		${PROJECT_SOURCE_DIR}/include
	)
	target_link_libraries(${name} PUBLIC
		fuzzing-common
		libmosquitto_common
		mosquitto_db_dump
	)
	install(TARGETS ${name}
		RUNTIME DESTINATION "${OUT}"
	)
endfunction()

add_db_dump_fuzzer(db_dump_fuzz_load)
add_db_dump_fuzzer(db_dump_fuzz_load_client_stats)
add_db_dump_fuzzer(db_dump_fuzz_load_stats)
