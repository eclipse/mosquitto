add_definitions(-DDEBUG)
add_compile_options(-Werror)
include_directories(${PROJECT_SOURCE_DIR}/lib ${PROJECT_SOURCE_DIR}/lib/cpp)

add_executable(01-con-discon-success-cpp 01-con-discon-success.cpp)
set_target_properties(01-con-discon-success-cpp PROPERTIES OUTPUT_NAME 01-con-discon-success.test)
target_link_libraries(01-con-discon-success-cpp mosquittopp)

add_executable(01-will-set-cpp 01-will-set.cpp)
set_target_properties(01-will-set-cpp PROPERTIES OUTPUT_NAME 01-will-set.test)
target_link_libraries(01-will-set-cpp mosquittopp)

add_executable(01-unpwd-set-cpp 01-unpwd-set.cpp)
set_target_properties(01-unpwd-set-cpp PROPERTIES OUTPUT_NAME 01-unpwd-set.test)
target_link_libraries(01-unpwd-set-cpp mosquittopp)

add_executable(01-will-unpwd-set-cpp 01-will-unpwd-set.cpp)
set_target_properties(01-will-unpwd-set-cpp PROPERTIES OUTPUT_NAME 01-will-unpwd-set.test)
target_link_libraries(01-will-unpwd-set-cpp mosquittopp)

add_executable(01-no-clean-session-cpp 01-no-clean-session.cpp)
set_target_properties(01-no-clean-session-cpp PROPERTIES OUTPUT_NAME 01-no-clean-session.test)
target_link_libraries(01-no-clean-session-cpp mosquittopp)

add_executable(01-keepalive-pingreq-cpp 01-keepalive-pingreq.cpp)
set_target_properties(01-keepalive-pingreq-cpp PROPERTIES OUTPUT_NAME 01-keepalive-pingreq.test)
target_link_libraries(01-keepalive-pingreq-cpp mosquittopp)

add_executable(02-subscribe-qos0-cpp 02-subscribe-qos0.cpp)
set_target_properties(02-subscribe-qos0-cpp PROPERTIES OUTPUT_NAME 02-subscribe-qos0.test)
target_link_libraries(02-subscribe-qos0-cpp mosquittopp)

add_executable(02-subscribe-qos1-cpp 02-subscribe-qos1.cpp)
set_target_properties(02-subscribe-qos1-cpp PROPERTIES OUTPUT_NAME 02-subscribe-qos1.test)
target_link_libraries(02-subscribe-qos1-cpp mosquittopp)

add_executable(02-subscribe-qos2-cpp 02-subscribe-qos2.cpp)
set_target_properties(02-subscribe-qos2-cpp PROPERTIES OUTPUT_NAME 02-subscribe-qos2.test)
target_link_libraries(02-subscribe-qos2-cpp mosquittopp)

add_executable(02-unsubscribe-cpp 02-unsubscribe.cpp)
set_target_properties(02-unsubscribe-cpp PROPERTIES OUTPUT_NAME 02-unsubscribe.test)
target_link_libraries(02-unsubscribe-cpp mosquittopp)

add_executable(03-publish-qos0-cpp 03-publish-qos0.cpp)
set_target_properties(03-publish-qos0-cpp PROPERTIES OUTPUT_NAME 03-publish-qos0.test)
target_link_libraries(03-publish-qos0-cpp mosquittopp)

add_executable(03-publish-qos0-no-payload-cpp 03-publish-qos0-no-payload.cpp)
set_target_properties(03-publish-qos0-no-payload-cpp PROPERTIES OUTPUT_NAME 03-publish-qos0-no-payload.test)
target_link_libraries(03-publish-qos0-no-payload-cpp mosquittopp)

add_executable(03-publish-c2b-qos1-disconnect-cpp 03-publish-c2b-qos1-disconnect.cpp)
set_target_properties(03-publish-c2b-qos1-disconnect-cpp PROPERTIES OUTPUT_NAME 03-publish-c2b-qos1-disconnect.test)
target_link_libraries(03-publish-c2b-qos1-disconnect-cpp mosquittopp)

add_executable(03-publish-c2b-qos2-cpp 03-publish-c2b-qos2.cpp)
set_target_properties(03-publish-c2b-qos2-cpp PROPERTIES OUTPUT_NAME 03-publish-c2b-qos2.test)
target_link_libraries(03-publish-c2b-qos2-cpp mosquittopp)

add_executable(03-publish-c2b-qos2-disconnect-cpp 03-publish-c2b-qos2-disconnect.cpp)
set_target_properties(03-publish-c2b-qos2-disconnect-cpp PROPERTIES OUTPUT_NAME 03-publish-c2b-qos2-disconnect.test)
target_link_libraries(03-publish-c2b-qos2-disconnect-cpp mosquittopp)

add_executable(03-publish-b2c-qos1-cpp 03-publish-b2c-qos1.cpp)
set_target_properties(03-publish-b2c-qos1-cpp PROPERTIES OUTPUT_NAME 03-publish-b2c-qos1.test)
target_link_libraries(03-publish-b2c-qos1-cpp mosquittopp)

add_executable(03-publish-b2c-qos2-cpp 03-publish-b2c-qos2.cpp)
set_target_properties(03-publish-b2c-qos2-cpp PROPERTIES OUTPUT_NAME 03-publish-b2c-qos2.test)
target_link_libraries(03-publish-b2c-qos2-cpp mosquittopp)

add_executable(04-retain-qos0-cpp 04-retain-qos0.cpp)
set_target_properties(04-retain-qos0-cpp PROPERTIES OUTPUT_NAME 04-retain-qos0.test)
target_link_libraries(04-retain-qos0-cpp mosquittopp)

add_executable(08-ssl-connect-no-auth-cpp 08-ssl-connect-no-auth.cpp)
set_target_properties(08-ssl-connect-no-auth-cpp PROPERTIES OUTPUT_NAME 08-ssl-connect-no-auth.test)
target_link_libraries(08-ssl-connect-no-auth-cpp mosquittopp)

add_executable(08-ssl-connect-cert-auth-cpp 08-ssl-connect-cert-auth.cpp)
set_target_properties(08-ssl-connect-cert-auth-cpp PROPERTIES OUTPUT_NAME 08-ssl-connect-cert-auth.test)
target_link_libraries(08-ssl-connect-cert-auth-cpp mosquittopp)

add_executable(08-ssl-connect-cert-auth-enc-cpp 08-ssl-connect-cert-auth-enc.cpp)
set_target_properties(08-ssl-connect-cert-auth-enc-cpp PROPERTIES OUTPUT_NAME 08-ssl-connect-cert-auth-enc.test)
target_link_libraries(08-ssl-connect-cert-auth-enc-cpp mosquittopp)

add_executable(08-ssl-bad-cacert-cpp 08-ssl-bad-cacert.cpp)
set_target_properties(08-ssl-bad-cacert-cpp PROPERTIES OUTPUT_NAME 08-ssl-bad-cacert.test)
target_link_libraries(08-ssl-bad-cacert-cpp mosquittopp)

add_executable(08-ssl-fake-cacert-cpp 08-ssl-fake-cacert.cpp)
set_target_properties(08-ssl-fake-cacert-cpp PROPERTIES OUTPUT_NAME 08-ssl-fake-cacert.test)
target_link_libraries(08-ssl-fake-cacert-cpp mosquittopp)

add_executable(09-util-topic-matching-cpp 09-util-topic-matching.cpp)
set_target_properties(09-util-topic-matching-cpp PROPERTIES OUTPUT_NAME 09-util-topic-matching.test)
target_link_libraries(09-util-topic-matching-cpp mosquittopp)

add_executable(09-util-topic-tokenise-cpp 09-util-topic-tokenise.cpp)
set_target_properties(09-util-topic-tokenise-cpp PROPERTIES OUTPUT_NAME 09-util-topic-tokenise.test)
target_link_libraries(09-util-topic-tokenise-cpp mosquittopp)
