add_library(mosquittopp SHARED mosquittopp.cpp)

target_include_directories(mosquittopp
	PUBLIC
	"${CMAKE_CURRENT_SOURCE_DIR}"
)
target_link_libraries(mosquittopp
	PUBLIC
	libmosquitto
)
install(TARGETS mosquittopp RUNTIME DESTINATION "${BINDIR}" LIBRARY DESTINATION "${LIBDIR}")
install(FILES mosquittopp.h DESTINATION "${INCLUDEDIR}")

set_target_properties(mosquittopp PROPERTIES
	VERSION ${VERSION}
	SOVERSION 1
)
if (UNIX)
	install(CODE "EXEC_PROGRAM(/sbin/ldconfig)")
endif (UNIX)
