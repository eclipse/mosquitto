add_subdirectory(lib)
add_subdirectory(broker)

add_compile_options(-Wall -ggdb)
add_definitions(-DDEBUG -DWITH_CLIENT)

add_executable(fake_user fake_user.c)
target_link_libraries(fake_user libmosquitto)
target_include_directories(fake_user PUBLIC ${PROJECT_SOURCE_DIR}/lib)

add_executable(msgsps_pub msgsps_pub.c msgsps_common.h)
target_link_libraries(msgsps_pub libmosquitto)
target_include_directories(msgsps_pub PUBLIC ${CMAKE_CURRENT_SOURCE_DIR} ${PROJECT_SOURCE_DIR}/lib)

add_executable(msgsps_sub msgsps_sub.c msgsps_common.h)
target_link_libraries(msgsps_sub libmosquitto)
target_include_directories(msgsps_sub PUBLIC ${CMAKE_CURRENT_SOURCE_DIR} ${PROJECT_SOURCE_DIR}/lib)
