add_executable(mosquitto_pub pub_client.c )
add_executable(mosquitto_sub sub_client.c sub_client_output.c)

foreach(CLIENT mosquitto_pub mosquitto_sub)
	target_sources(${CLIENT} PRIVATE client_shared.c)
	target_link_libraries(${CLIENT} PRIVATE libmosquitto)

	if (${WITH_SRV} STREQUAL ON)
		target_compile_definitions(${CLIENT} PRIVATE WITH_SRV)
	endif (${WITH_SRV} STREQUAL ON)

	install(TARGETS ${CLIENT} RUNTIME DESTINATION "${BINDIR}" LIBRARY DESTINATION "${LIBDIR}")
endforeach(CLIENT)
