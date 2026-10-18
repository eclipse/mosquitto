find_package(mallocfail CONFIG REQUIRED)

add_library(fuzzing-common INTERFACE)
if(DEFINED ENV{LIB_FUZZING_ENGINE})
	set(FUZZ_FLAGS "$ENV{LIB_FUZZING_ENGINE}")
	target_compile_options(fuzzing-common INTERFACE ${FUZZ_FLAGS})
	target_link_options(fuzzing-common INTERFACE ${FUZZ_FLAGS})
endif()

if(DEFINED ENV{OUT})
	set(OUT "$ENV{OUT}")
else()
	set(OUT "${CMAKE_BINARY_DIR}")
endif()

if(DEFINED ENV{SRC} AND EXISTS "$ENV{SRC}/LPM/src/libprotobuf-mutator.a")
	set(LPM_DIR "$ENV{SRC}/LPM")
	add_library(libprotobuf_mutator INTERFACE)
	target_include_directories(libprotobuf_mutator INTERFACE
		$ENV{SRC}/libprotobuf-mutator
		$ENV{SRC}/LPM/external.protobuf/include
	)
	file(GLOB LPM_LIBS
		"$ENV{SRC}/LPM/src/libfuzzer/*.a"
		"$ENV{SRC}/LPM/src/*.a"
		"$ENV{SRC}/LPM/external.protobuf/lib/*.a"
	)
	target_link_libraries(libprotobuf_mutator INTERFACE
		"$<LINK_GROUP:RESCAN,${LPM_LIBS}>"
	)
	set(LPM_PROTOC "$ENV{SRC}/LPM/external.protobuf/bin/protoc")
else()
	message(FATAL_ERROR "libprotobuf-mutator not found")
endif()

function(lpm_protoc name)
	message("${name}")
	message("${LPM_PROTOC}")
	add_custom_command(
		OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/${name}.pb.cc ${CMAKE_CURRENT_BINARY_DIR}/${name}.pb.h
		COMMAND ${LPM_PROTOC}
			--cpp_out=${CMAKE_CURRENT_BINARY_DIR}
			--proto_path=${CMAKE_CURRENT_SOURCE_DIR}
			${name}.proto
		DEPENDS ${name}.proto
		COMMENT "protoc ${name}.proto"
		VERBATIM
	)
endfunction()

add_subdirectory(apps)
add_subdirectory(broker)
add_subdirectory(corpora)
add_subdirectory(libcommon)
add_subdirectory(plugins)
