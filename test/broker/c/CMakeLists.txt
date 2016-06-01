add_compile_options(-Wall -Werror)

add_library(auth_plugin SHARED auth_plugin.c)
set_target_properties(auth_plugin PROPERTIES PREFIX "" SUFFIX ".so")
target_include_directories(auth_plugin PUBLIC ${PROJECT_SOURCE_DIR}/lib ${PROJECT_SOURCE_DIR}/src)

add_executable(08-tls-psk-pub.test 08-tls-psk-pub.c)
target_link_libraries(08-tls-psk-pub.test libmosquitto)
target_include_directories(08-tls-psk-pub.test PUBLIC ${PROJECT_SOURCE_DIR}/lib)

add_executable(08-tls-psk-bridge.test 08-tls-psk-bridge.c)
target_link_libraries(08-tls-psk-bridge.test libmosquitto)
target_include_directories(08-tls-psk-bridge.test PUBLIC ${PROJECT_SOURCE_DIR}/lib)
