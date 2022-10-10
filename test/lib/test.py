#!/usr/bin/env python3

import mosq_test_helper
import ptest

tests = [
    (1, ['./01-con-discon-success.py', 'c/01-con-discon-success.test']),
    (1, ['./01-con-discon-success-v5.py', 'c/01-con-discon-success-v5.test']),
    (1, ['./01-con-discon-will.py', 'c/01-con-discon-will.test']),
    (1, ['./01-con-discon-will-v5.py', 'c/01-con-discon-will-v5.test']),
    (1, ['./01-con-discon-will-clear.py', 'c/01-con-discon-will-clear.test']),
    (1, ['./01-keepalive-pingreq.py', 'c/01-keepalive-pingreq.test']),
    (1, ['./01-no-clean-session.py', 'c/01-no-clean-session.test']),
    (1, ['./01-server-keepalive-pingreq.py', 'c/01-server-keepalive-pingreq.test']),
    (1, ['./01-unpwd-set.py', 'c/01-unpwd-set.test']),
    (1, ['./01-will-set.py', 'c/01-will-set.test']),
    (1, ['./01-will-unpwd-set.py', 'c/01-will-unpwd-set.test']),

    (1, ['./02-subscribe-qos0.py', 'c/02-subscribe-qos0.test']),
    (1, ['./02-subscribe-qos1.py', 'c/02-subscribe-qos1.test']),
    (1, ['./02-subscribe-qos1.py', 'c/02-subscribe-qos1-async1.test']),
    (1, ['./02-subscribe-qos1.py', 'c/02-subscribe-qos1-async2.test']),
    (1, ['./02-subscribe-qos2.py', 'c/02-subscribe-qos2.test']),
    (1, ['./02-unsubscribe-multiple-v5.py', 'c/02-unsubscribe-multiple-v5.test']),
    (1, ['./02-unsubscribe-v5.py', 'c/02-unsubscribe-v5.test']),
    (1, ['./02-unsubscribe.py', 'c/02-unsubscribe.test']),

    (1, ['./03-publish-b2c-qos1.py', 'c/03-publish-b2c-qos1.test']),
    (1, ['./03-publish-b2c-qos1-unexpected-puback.py', 'c/03-publish-b2c-qos1-unexpected-puback.test']),
    (1, ['./03-publish-b2c-qos2-len.py', 'c/03-publish-b2c-qos2-len.test']),
    (1, ['./03-publish-b2c-qos2-unexpected-pubrel.py', 'c/03-publish-b2c-qos2-unexpected-pubrel.test']),
    (1, ['./03-publish-b2c-qos2-unexpected-pubcomp.py', 'c/03-publish-b2c-qos2-unexpected-pubcomp.test']),
    (1, ['./03-publish-b2c-qos2.py', 'c/03-publish-b2c-qos2.test']),
    (1, ['./03-publish-c2b-qos1-disconnect.py', 'c/03-publish-c2b-qos1-disconnect.test']),
    (1, ['./03-publish-c2b-qos1-len.py', 'c/03-publish-c2b-qos1-len.test']),
    (1, ['./03-publish-c2b-qos1-receive-maximum.py', 'c/03-publish-c2b-qos1-receive-maximum.test']),
    (1, ['./03-publish-c2b-qos2-disconnect.py', 'c/03-publish-c2b-qos2-disconnect.test']),
    (1, ['./03-publish-c2b-qos2-len.py', 'c/03-publish-c2b-qos2-len.test']),
    (1, ['./03-publish-c2b-qos2-maximum-qos-0.py', 'c/03-publish-c2b-qos2-maximum-qos-0.test']),
    (1, ['./03-publish-c2b-qos2-maximum-qos-1.py', 'c/03-publish-c2b-qos2-maximum-qos-1.test']),
    (1, ['./03-publish-c2b-qos2-pubrec-error.py', 'c/03-publish-c2b-qos2-pubrec-error.test']),
    (1, ['./03-publish-c2b-qos2-receive-maximum-1.py', 'c/03-publish-c2b-qos2-receive-maximum-1.test']),
    (1, ['./03-publish-c2b-qos2-receive-maximum-2.py', 'c/03-publish-c2b-qos2-receive-maximum-2.test']),
    (1, ['./03-publish-c2b-qos2.py', 'c/03-publish-c2b-qos2.test']),
    (1, ['./03-publish-qos0-no-payload.py', 'c/03-publish-qos0-no-payload.test']),
    (1, ['./03-publish-qos0.py', 'c/03-publish-qos0.test']),
    (1, ['./03-request-response-correlation.py', 'c/03-request-response-correlation.test']),
    (1, ['./03-request-response.py', 'c/03-request-response.test']),

    (1, ['./04-retain-qos0.py', 'c/04-retain-qos0.test']),

    (1, ['./08-ssl-bad-cacert.py', 'c/08-ssl-bad-cacert.test']),
    (1, ['./08-ssl-connect-cert-auth-enc.py', 'c/08-ssl-connect-cert-auth-enc.test']),
    (1, ['./08-ssl-connect-cert-auth.py', 'c/08-ssl-connect-cert-auth.test']),
    (1, ['./08-ssl-connect-cert-auth.py', 'c/08-ssl-connect-cert-auth-custom-ssl-ctx.test']),
    (1, ['./08-ssl-connect-cert-auth.py', 'c/08-ssl-connect-cert-auth-custom-ssl-ctx-default.test']),
    (1, ['./08-ssl-connect-no-auth.py', 'c/08-ssl-connect-no-auth.test']),

    (1, ['./09-util-topic-tokenise.py', 'c/09-util-topic-tokenise.test']),

    (1, ['./11-prop-oversize-packet.py', 'c/11-prop-oversize-packet.test']),
    (1, ['./11-prop-send-content-type.py', 'c/11-prop-send-content-type.test']),
    (1, ['./11-prop-send-payload-format.py', 'c/11-prop-send-payload-format.test']),


    (1, ['./01-con-discon-success.py', 'cpp/01-con-discon-success.test']),
    (1, ['./01-keepalive-pingreq.py', 'cpp/01-keepalive-pingreq.test']),
    (1, ['./01-no-clean-session.py', 'cpp/01-no-clean-session.test']),
    (1, ['./01-unpwd-set.py', 'cpp/01-unpwd-set.test']),
    (1, ['./01-will-set.py', 'cpp/01-will-set.test']),
    (1, ['./01-will-unpwd-set.py', 'cpp/01-will-unpwd-set.test']),

    (1, ['./02-subscribe-qos0.py', 'cpp/02-subscribe-qos0.test']),
    (1, ['./02-subscribe-qos1.py', 'cpp/02-subscribe-qos1.test']),
    (1, ['./02-subscribe-qos2.py', 'cpp/02-subscribe-qos2.test']),
    (1, ['./02-unsubscribe.py', 'cpp/02-unsubscribe.test']),

    (1, ['./03-publish-b2c-qos1.py', 'cpp/03-publish-b2c-qos1.test']),
    (1, ['./03-publish-b2c-qos2.py', 'cpp/03-publish-b2c-qos2.test']),
    (1, ['./03-publish-c2b-qos1-disconnect.py', 'cpp/03-publish-c2b-qos1-disconnect.test']),
    (1, ['./03-publish-c2b-qos2-disconnect.py', 'cpp/03-publish-c2b-qos2-disconnect.test']),
    (1, ['./03-publish-c2b-qos2.py', 'cpp/03-publish-c2b-qos2.test']),
    (1, ['./03-publish-qos0-no-payload.py', 'cpp/03-publish-qos0-no-payload.test']),
    (1, ['./03-publish-qos0.py', 'cpp/03-publish-qos0.test']),

    (1, ['./04-retain-qos0.py', 'cpp/04-retain-qos0.test']),

    (1, ['./08-ssl-bad-cacert.py', 'cpp/08-ssl-bad-cacert.test']),
    (1, ['./08-ssl-connect-cert-auth-enc.py', 'cpp/08-ssl-connect-cert-auth-enc.test']),
    (1, ['./08-ssl-connect-cert-auth.py', 'cpp/08-ssl-connect-cert-auth.test']),
    (1, ['./08-ssl-connect-no-auth.py', 'cpp/08-ssl-connect-no-auth.test']),

    (1, ['./09-util-topic-tokenise.py', 'cpp/09-util-topic-tokenise.test']),
    ]


ptest.run_tests(tests)
