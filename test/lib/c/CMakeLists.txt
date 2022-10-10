set(BINARIES
    01-con-discon-success
    01-con-discon-success-v5
    01-con-discon-will
    01-con-discon-will-v5
    01-con-discon-will-clear
    01-keepalive-pingreq
    01-no-clean-session
    01-pre-connect-callback
    01-server-keepalive-pingreq
    01-unpwd-set
    01-will-set
    01-will-unpwd-set
    02-subscribe-qos0
    02-subscribe-qos1-async1
    02-subscribe-qos1-async2
    02-subscribe-qos1
    02-subscribe-qos2
    02-unsubscribe-multiple-v5
    02-unsubscribe-v5
    02-unsubscribe
    03-publish-b2c-qos1-unexpected-puback
    03-publish-b2c-qos1
    03-publish-b2c-qos2-len
    03-publish-b2c-qos2-unexpected-pubrel
    03-publish-b2c-qos2-unexpected-pubcomp
    03-publish-b2c-qos2
    03-publish-c2b-qos1-disconnect
    03-publish-c2b-qos1-len
    03-publish-c2b-qos1-receive-maximum
    03-publish-c2b-qos2-disconnect
    03-publish-c2b-qos2-len
    03-publish-c2b-qos2-maximum-qos-0
    03-publish-c2b-qos2-maximum-qos-1
    03-publish-c2b-qos2-pubrec-error
    03-publish-c2b-qos2-receive-maximum-1
    03-publish-c2b-qos2-receive-maximum-2
    03-publish-c2b-qos2
    03-publish-qos0-no-payload
    03-publish-qos0
    03-request-response-1
    03-request-response-2
    03-request-response-correlation-1
    04-retain-qos0
    08-ssl-bad-cacert
    08-ssl-connect-cert-auth-enc
    08-ssl-connect-cert-auth
    08-ssl-connect-no-auth
    08-ssl-fake-cacert
    09-util-topic-tokenise
    11-prop-oversize-packet
    11-prop-recv-qos0
    11-prop-recv-qos1
    11-prop-recv-qos2
    11-prop-send-payload-format
    11-prop-send-content-type
)

foreach(BINARY ${BINARIES})
    add_executable(${BINARY} ${BINARY}.c)
    target_compile_definitions(${BINARY} PRIVATE TEST_SOURCE_DIR="${CMAKE_CURRENT_SOURCE_DIR}")
    target_include_directories(${BINARY} PRIVATE ${CMAKE_SOURCE_DIR}/test)
    set_property(TARGET ${BINARY} PROPERTY SUFFIX .test)
    target_link_libraries(${BINARY} PRIVATE common-options libmosquitto)
endforeach()
