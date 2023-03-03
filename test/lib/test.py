#!/usr/bin/env python3

import mosq_test_helper
import ptest

tests = [
    (1, './01-con-discon-success-v5.py'),
    (1, './01-con-discon-success.py'),
    (1, './01-con-discon-will-clear.py'),
    (1, './01-con-discon-will-v5.py'),
    (1, './01-con-discon-will.py'),
    (1, './01-keepalive-pingreq.py'),
    (1, './01-no-clean-session.py'),
    (1, './01-server-keepalive-pingreq.py'),
    (1, './01-unpwd-set.py'),
    (1, './01-will-set.py'),
    (1, './01-will-unpwd-set.py'),

    (1, './02-subscribe-qos0.py'),
    (1, './02-subscribe-qos1.py'),
    (1, './02-subscribe-qos2.py'),
    (1, './02-unsubscribe-multiple-v5.py'),
    (1, './02-unsubscribe-v5.py'),
    (1, './02-unsubscribe.py'),

    (1, './03-publish-b2c-qos1-unexpected-puback.py'),
    (1, './03-publish-b2c-qos1.py'),
    (1, './03-publish-b2c-qos2-len.py'),
    (1, './03-publish-b2c-qos2-unexpected-pubcomp.py'),
    (1, './03-publish-b2c-qos2-unexpected-pubrel.py'),
    (1, './03-publish-b2c-qos2.py'),
    (1, './03-publish-c2b-qos1-disconnect.py'),
    (1, './03-publish-c2b-qos1-len.py'),
    (1, './03-publish-c2b-qos1-receive-maximum.py'),
    (1, './03-publish-c2b-qos2-disconnect.py'),
    (1, './03-publish-c2b-qos2-len.py'),
    (1, './03-publish-c2b-qos2-maximum-qos-0.py'),
    (1, './03-publish-c2b-qos2-maximum-qos-1.py'),
    (1, './03-publish-c2b-qos2-pubrec-error.py'),
    (1, './03-publish-c2b-qos2-receive-maximum-1.py'),
    (1, './03-publish-c2b-qos2-receive-maximum-2.py'),
    (1, './03-publish-c2b-qos2.py'),
    (1, './03-publish-qos0-no-payload.py'),
    (1, './03-publish-qos0.py'),
    (1, './03-request-response-correlation.py'),
    (1, './03-request-response.py'),

    (1, './04-retain-qos0.py'),

    (1, './08-ssl-bad-cacert.py'),
    (1, './08-ssl-connect-cert-auth-enc.py'),
    (1, './08-ssl-connect-cert-auth.py'),
    (1, './08-ssl-connect-no-auth.py'),
    (1, './08-ssl-connect-san.py'),

    (1, './09-util-topic-tokenise.py'),

    (1, './11-prop-oversize-packet.py'),
    (1, './11-prop-send-content-type.py'),
    (1, './11-prop-send-payload-format.py'),
    ]


ptest.run_tests(tests)
