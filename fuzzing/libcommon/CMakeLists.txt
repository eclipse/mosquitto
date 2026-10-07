function(add_libcommon_fuzzer name)
	add_executable(${name} ${name}.cpp)
	target_include_directories(${name} PRIVATE
		${PROJECT_SOURCE_DIR}
		${PROJECT_SOURCE_DIR}/include
	)
	target_link_libraries(${name} PUBLIC
		fuzzing-common
		libmosquitto_common
	)
	install(TARGETS ${name}
		RUNTIME DESTINATION "${OUT}"
	)
endfunction()

function(add_libcommon_lpm_fuzzer name)
	lpm_protoc(${name})
	add_libcommon_fuzzer(${name})
	target_sources(${name} PRIVATE
		${CMAKE_CURRENT_BINARY_DIR}/${name}.pb.cc
		${CMAKE_CURRENT_BINARY_DIR}/${name}.pb.h
	)
	target_include_directories(${name} PRIVATE
		${CMAKE_CURRENT_BINARY_DIR}
	)
	target_link_libraries(${name} PUBLIC
		libprotobuf_mutator
	)
endfunction()

add_libcommon_fuzzer(libcommon_fuzz_pub_topic_check2)
add_libcommon_fuzzer(libcommon_fuzz_sub_topic_check2)
add_libcommon_fuzzer(libcommon_fuzz_topic_tokenise)
add_libcommon_fuzzer(libcommon_fuzz_utf8)

add_libcommon_lpm_fuzzer(libcommon_fuzz_property)
add_libcommon_lpm_fuzzer(libcommon_fuzz_topic_matching)
