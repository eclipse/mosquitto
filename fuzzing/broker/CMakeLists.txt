add_library(broker-fuzzing-common INTERFACE)
target_compile_definitions(broker-fuzzing-common INTERFACE
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

target_include_directories(broker-fuzzing-common INTERFACE
	${PROJECT_SOURCE_DIR}/include
	${PROJECT_SOURCE_DIR}/lib
	${PROJECT_SOURCE_DIR}/src
)

target_link_libraries(broker-fuzzing-common INTERFACE
	fuzzing-common
	libmosquitto_common
	mosquitto
	mallocfail::wrap
)

add_library(fuzz-packet-read-base OBJECT
	fuzz_packet_read_base.c
	fuzz_packet_read_base.h
)
target_link_libraries(fuzz-packet-read-base PUBLIC
	broker-fuzzing-common
)

function(add_broker_fuzzer name)
	add_executable(${name} ${name}.cpp)
	target_link_libraries(${name} PRIVATE
		broker-fuzzing-common
	)
	install(TARGETS ${name}
		RUNTIME DESTINATION "${OUT}"
	)
endfunction()

function(add_broker_packet_fuzzer name)
	add_executable(${name} ${name}.cpp)
	target_link_libraries(${name} PRIVATE
		broker-fuzzing-common
		fuzz-packet-read-base
	)
	install(TARGETS ${name}
		RUNTIME DESTINATION "${OUT}"
	)
endfunction()

add_broker_fuzzer(broker_fuzz_acl_file)
add_broker_fuzzer(broker_fuzz_password_file)
add_broker_fuzzer(broker_fuzz_proxy_v1)
add_broker_fuzzer(broker_fuzz_proxy_v2)
add_broker_fuzzer(broker_fuzz_psk_file)
add_broker_fuzzer(broker_fuzz_queue_msg)
add_broker_fuzzer(broker_fuzz_test_config)

add_broker_packet_fuzzer(broker_fuzz_handle_auth)
add_broker_packet_fuzzer(broker_fuzz_handle_connect)
add_broker_packet_fuzzer(broker_fuzz_handle_publish)
add_broker_packet_fuzzer(broker_fuzz_handle_subscribe)
add_broker_packet_fuzzer(broker_fuzz_handle_unsubscribe)
add_broker_packet_fuzzer(broker_fuzz_read_handle)

#cp ${R}/fuzzing/corpora/broker_acl_file_seed_corpus.zip ${OUT}/broker_fuzz_acl_file_seed_corpus.zip
#cp ${R}/fuzzing/corpora/broker_acl_file.dict ${OUT}/broker_fuzz_acl_file.dict
#cp ${R}/fuzzing/corpora/broker_password_file_seed_corpus.zip ${OUT}/broker_fuzz_password_file_seed_corpus.zip
#cp ${R}/fuzzing/corpora/broker_fuzz_proxy_v1_seed_corpus.zip ${OUT}/broker_fuzz_proxy_v1_seed_corpus.zip
#cp ${R}/fuzzing/corpora/broker_fuzz_proxy_v2_seed_corpus.zip ${OUT}/broker_fuzz_proxy_v2_seed_corpus.zip
#cp ${R}/fuzzing/corpora/broker_psk_file_seed_corpus.zip ${OUT}/broker_fuzz_psk_file_seed_corpus.zip
#cp ${R}/fuzzing/corpora/broker_queue_msg_seed_corpus.zip ${OUT}/broker_fuzz_queue_msg_seed_corpus.zip
#cp ${R}/fuzzing/corpora/broker_packet_seed_corpus.zip ${OUT}/broker_fuzz_read_handle_seed_corpus.zip
#cp ${R}/fuzzing/corpora/broker_fuzz_test_config_seed_corpus.zip ${OUT}/broker_fuzz_test_config_seed_corpus.zip
#cp ${R}/fuzzing/corpora/broker_conf.dict ${OUT}/broker_fuzz_test_config.dict
