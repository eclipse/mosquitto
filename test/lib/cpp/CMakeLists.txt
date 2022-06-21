set(BINARIES
    01-con-discon-success
    01-will-set
    01-unpwd-set
    01-will-unpwd-set
    01-no-clean-session
    01-keepalive-pingreq
    02-subscribe-qos0
    02-subscribe-qos1
    02-subscribe-qos2
    02-unsubscribe
    03-publish-qos0
    03-publish-qos0-no-payload
    03-publish-c2b-qos1-disconnect
    03-publish-c2b-qos2
    03-publish-c2b-qos2-disconnect
    03-publish-b2c-qos1
    03-publish-b2c-qos2
    04-retain-qos0
    08-ssl-connect-no-auth
    08-ssl-connect-cert-auth
    08-ssl-connect-cert-auth-enc
    08-ssl-bad-cacert
    08-ssl-fake-cacert
    09-util-topic-tokenise
)

foreach(BINARY ${BINARIES})
    set(TARGET "${BINARY}-cpp")
    add_executable(${TARGET}
        ${BINARY}.cpp
    )
    set_property(TARGET ${TARGET}
        PROPERTY SUFFIX .test
    )
    target_link_libraries(${TARGET} PRIVATE mosquittopp)
endforeach()
