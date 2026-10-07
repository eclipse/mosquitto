function(add_dynsec_fuzzer name)
	add_executable(${name} ${name}.cpp)
	target_compile_definitions(${name} PRIVATE
		WITH_BRIDGE
		WITH_BROKER
		WITH_CONTROL
		WITH_EPOLL
		WITH_MEMORY_TRACKING
		WITH_PERSISTENCE
		WITH_SOCKS
		WITH_SYSTEMD
		WITH_SYS_TREE
		WITH_TLS
		WITH_TLS_PSK
		WITH_UNIX_SOCKETS
		WITH_WEBSOCKETS=WS_IS_BUILTIN
	)
	target_include_directories(${name} PRIVATE
		${PROJECT_SOURCE_DIR}
		${PROJECT_SOURCE_DIR}/include
		${PROJECT_SOURCE_DIR}/lib
		${PROJECT_SOURCE_DIR}/src
	)
	target_link_libraries(${name} PUBLIC
		fuzzing-common
		libmosquitto_common
		mosquitto_dynamic_security
		mosquitto
	)
	install(TARGETS ${name}
		RUNTIME DESTINATION "${OUT}"
	)
endfunction()

add_dynsec_fuzzer(dynsec_fuzz_load)
#cp ${R}/fuzzing/corpora/dynsec_config_seed_corpus.zip ${OUT}/$@_seed_corpus.zip
