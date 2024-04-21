# If we are building from a release tarball, the man pages should already be built, so them.
# If we are building from git, then the man pages will not be built. In this
# case, attempt to find xsltproc, and if found build the man pages. If xsltproc
# could not be found, then the man pages will not be built or installed -
# because the install is optional.

find_program(XSLTPROC xsltproc OPTIONAL)
if(XSLTPROC AND NOT WIN32)
	function(compile_manpage page)
		add_custom_command(OUTPUT ${PROJECT_SOURCE_DIR}/man/${page}
			COMMAND xsltproc ${PROJECT_SOURCE_DIR}/man/${page}.xml -o ${PROJECT_SOURCE_DIR}/man/
			MAIN_DEPENDENCY ${PROJECT_SOURCE_DIR}/man/${page}.xml)
		add_custom_target(${page} ALL DEPENDS ${PROJECT_SOURCE_DIR}/man/${page})
	endfunction()

	compile_manpage("mosquitto_ctrl.1")
	compile_manpage("mosquitto_ctrl_dynsec.1")
	compile_manpage("mosquitto_passwd.1")
	compile_manpage("mosquitto_pub.1")
	compile_manpage("mosquitto_sub.1")
	compile_manpage("mosquitto_rr.1")
	compile_manpage("libmosquitto.3")
	compile_manpage("mosquitto.conf.5")
	compile_manpage("mosquitto-tls.7")
	compile_manpage("mqtt.7")
	compile_manpage("mosquitto.8")

	install(FILES
		mosquitto_ctrl.1
		mosquitto_ctrl_dynsec.1
		mosquitto_passwd.1
		mosquitto_pub.1
		mosquitto_sub.1
		mosquitto_rr.1
		DESTINATION ${CMAKE_INSTALL_MANDIR}/man1
		OPTIONAL)

	install(FILES libmosquitto.3 DESTINATION ${CMAKE_INSTALL_MANDIR}/man3 OPTIONAL)
	install(FILES mosquitto.conf.5 DESTINATION ${CMAKE_INSTALL_MANDIR}/man5 OPTIONAL)
	install(FILES mosquitto-tls.7 mqtt.7 DESTINATION ${CMAKE_INSTALL_MANDIR}/man7 OPTIONAL)
	install(FILES mosquitto.8 DESTINATION ${CMAKE_INSTALL_MANDIR}/man8 OPTIONAL)

elseif(WIN32)
	message(WARNING "xsltproc not found: manpages cannot be built")
else()
	message(FATAL_ERROR "xsltproc not found: manpages cannot be built")
endif()

