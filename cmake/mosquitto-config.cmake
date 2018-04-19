include(CMakeFindDependencyMacro)

include("${CMAKE_CURRENT_LIST_DIR}/mosquitto-targets.cmake")

find_dependency(OpenSSL REQUIRED)
find_dependency(Libwebsockets REQUIRED)
