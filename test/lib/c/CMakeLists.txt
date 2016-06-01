add_compile_options(-Werror)
include_directories(${PROJECT_SOURCE_DIR}/lib)

add_executable(01-con-discon-success-c 01-con-discon-success.c)
set_target_properties(01-con-discon-success-c PROPERTIES OUTPUT_NAME 01-con-discon-success.test)
target_link_libraries(01-con-discon-success-c libmosquitto)

add_executable(01-will-set-c 01-will-set.c)
set_target_properties(01-will-set-c PROPERTIES OUTPUT_NAME 01-will-set.test)
target_link_libraries(01-will-set-c libmosquitto)

add_executable(01-unpwd-set-c 01-unpwd-set.c)
set_target_properties(01-unpwd-set-c PROPERTIES OUTPUT_NAME 01-unpwd-set.test)
target_link_libraries(01-unpwd-set-c libmosquitto)

add_executable(01-will-unpwd-set-c 01-will-unpwd-set.c)
set_target_properties(01-will-unpwd-set-c PROPERTIES OUTPUT_NAME 01-will-unpwd-set.test)
target_link_libraries(01-will-unpwd-set-c libmosquitto)

add_executable(01-no-clean-session-c 01-no-clean-session.c)
set_target_properties(01-no-clean-session-c PROPERTIES OUTPUT_NAME 01-no-clean-session.test)
target_link_libraries(01-no-clean-session-c libmosquitto)

add_executable(01-keepalive-pingreq-c 01-keepalive-pingreq.c)
set_target_properties(01-keepalive-pingreq-c PROPERTIES OUTPUT_NAME 01-keepalive-pingreq.test)
target_link_libraries(01-keepalive-pingreq-c libmosquitto)

add_executable(02-subscribe-qos0-c 02-subscribe-qos0.c)
set_target_properties(02-subscribe-qos0-c PROPERTIES OUTPUT_NAME 02-subscribe-qos0.test)
target_link_libraries(02-subscribe-qos0-c libmosquitto)

add_executable(02-subscribe-qos1-c 02-subscribe-qos1.c)
set_target_properties(02-subscribe-qos1-c PROPERTIES OUTPUT_NAME 02-subscribe-qos1.test)
target_link_libraries(02-subscribe-qos1-c libmosquitto)

add_executable(02-subscribe-qos2-c 02-subscribe-qos2.c)
set_target_properties(02-subscribe-qos2-c PROPERTIES OUTPUT_NAME 02-subscribe-qos2.test)
target_link_libraries(02-subscribe-qos2-c libmosquitto)

add_executable(02-unsubscribe-c 02-unsubscribe.c)
set_target_properties(02-unsubscribe-c PROPERTIES OUTPUT_NAME 02-unsubscribe.test)
target_link_libraries(02-unsubscribe-c libmosquitto)

add_executable(03-publish-qos0-c 03-publish-qos0.c)
set_target_properties(03-publish-qos0-c PROPERTIES OUTPUT_NAME 03-publish-qos0.test)
target_link_libraries(03-publish-qos0-c libmosquitto)

add_executable(03-publish-qos0-no-payload-c 03-publish-qos0-no-payload.c)
set_target_properties(03-publish-qos0-no-payload-c PROPERTIES OUTPUT_NAME 03-publish-qos0-no-payload.test)
target_link_libraries(03-publish-qos0-no-payload-c libmosquitto)

add_executable(03-publish-c2b-qos1-disconnect-c 03-publish-c2b-qos1-disconnect.c)
set_target_properties(03-publish-c2b-qos1-disconnect-c PROPERTIES OUTPUT_NAME 03-publish-c2b-qos1-disconnect.test)
target_link_libraries(03-publish-c2b-qos1-disconnect-c libmosquitto)

add_executable(03-publish-c2b-qos2-c 03-publish-c2b-qos2.c)
set_target_properties(03-publish-c2b-qos2-c PROPERTIES OUTPUT_NAME 03-publish-c2b-qos2.test)
target_link_libraries(03-publish-c2b-qos2-c libmosquitto)

add_executable(03-publish-c2b-qos2-disconnect-c 03-publish-c2b-qos2-disconnect.c)
set_target_properties(03-publish-c2b-qos2-disconnect-c PROPERTIES OUTPUT_NAME 03-publish-c2b-qos2-disconnect.test)
target_link_libraries(03-publish-c2b-qos2-disconnect-c libmosquitto)

add_executable(03-publish-b2c-qos1-c 03-publish-b2c-qos1.c)
set_target_properties(03-publish-b2c-qos1-c PROPERTIES OUTPUT_NAME 03-publish-b2c-qos1.test)
target_link_libraries(03-publish-b2c-qos1-c libmosquitto)

add_executable(03-publish-b2c-qos2-c 03-publish-b2c-qos2.c)
set_target_properties(03-publish-b2c-qos2-c PROPERTIES OUTPUT_NAME 03-publish-b2c-qos2.test)
target_link_libraries(03-publish-b2c-qos2-c libmosquitto)

add_executable(04-retain-qos0-c 04-retain-qos0.c)
set_target_properties(04-retain-qos0-c PROPERTIES OUTPUT_NAME 04-retain-qos0.test)
target_link_libraries(04-retain-qos0-c libmosquitto)

add_executable(08-ssl-connect-no-auth-c 08-ssl-connect-no-auth.c)
set_target_properties(08-ssl-connect-no-auth-c PROPERTIES OUTPUT_NAME 08-ssl-connect-no-auth.test)
target_link_libraries(08-ssl-connect-no-auth-c libmosquitto)

add_executable(08-ssl-connect-cert-auth-c 08-ssl-connect-cert-auth.c)
set_target_properties(08-ssl-connect-cert-auth-c PROPERTIES OUTPUT_NAME 08-ssl-connect-cert-auth.test)
target_link_libraries(08-ssl-connect-cert-auth-c libmosquitto)

add_executable(08-ssl-connect-cert-auth-enc-c 08-ssl-connect-cert-auth-enc.c)
set_target_properties(08-ssl-connect-cert-auth-enc-c PROPERTIES OUTPUT_NAME 08-ssl-connect-cert-auth-enc.test)
target_link_libraries(08-ssl-connect-cert-auth-enc-c libmosquitto)

add_executable(08-ssl-bad-cacert-c 08-ssl-bad-cacert.c)
set_target_properties(08-ssl-bad-cacert-c PROPERTIES OUTPUT_NAME 08-ssl-bad-cacert.test)
target_link_libraries(08-ssl-bad-cacert-c libmosquitto)

add_executable(08-ssl-fake-cacert-c 08-ssl-fake-cacert.c)
set_target_properties(08-ssl-fake-cacert-c PROPERTIES OUTPUT_NAME 08-ssl-fake-cacert.test)
target_link_libraries(08-ssl-fake-cacert-c libmosquitto)

add_executable(09-util-topic-matching-c 09-util-topic-matching.c)
set_target_properties(09-util-topic-matching-c PROPERTIES OUTPUT_NAME 09-util-topic-matching.test)
target_link_libraries(09-util-topic-matching-c libmosquitto)

add_executable(09-util-topic-tokenise-c 09-util-topic-tokenise.c)
set_target_properties(09-util-topic-tokenise-c PROPERTIES OUTPUT_NAME 09-util-topic-tokenise.test)
target_link_libraries(09-util-topic-tokenise-c libmosquitto)
