include_directories(${mosquitto_SOURCE_DIR}/lib
			${STDBOOL_H_PATH} ${STDINT_H_PATH})
link_directories(${mosquitto_BINARY_DIR}/lib)

set(shared_src client_shared.c client_shared.h)

if (${WITH_SRV} STREQUAL ON)
	add_definitions("-DWITH_SRV")
endif (${WITH_SRV} STREQUAL ON)

add_executable(mosquitto_pub pub_client.c ${shared_src})
add_executable(mosquitto_sub sub_client.c ${shared_src})
add_executable(mosquitto_bridge bridge_client.c ${shared_src})

target_link_libraries(mosquitto_pub libmosquitto)
target_link_libraries(mosquitto_sub libmosquitto)
target_link_libraries(mosquitto_bridge libmosquitto)

install(TARGETS mosquitto_pub RUNTIME DESTINATION "${BINDIR}" LIBRARY DESTINATION "${LIBDIR}")
install(TARGETS mosquitto_sub RUNTIME DESTINATION "${BINDIR}" LIBRARY DESTINATION "${LIBDIR}")
install(TARGETS mosquitto_bridge RUNTIME DESTINATION "${BINDIR}" LIBRARY DESTINATION "${LIBDIR}")
