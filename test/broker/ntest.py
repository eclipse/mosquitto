#!/usr/bin/env python3

import mosq_test_helper
import mosq_test
import os
import ptest
import threading
import importlib
import time

tests = [
    '01-connect-bad-packet',
    '01-connect-disconnect-v5',
    '01-connect-duplicate',
    '01-connect-invalid-id-0',
    '01-connect-invalid-id-missing',
    '01-connect-invalid-id-utf8',
    '01-connect-invalid-protonum',
    '01-connect-invalid-reserved',
    '01-connect-success',
    '01-connect-uname-invalid-utf8',
    '01-connect-uname-no-flag',
    '01-connect-uname-pwd-no-flag',

    '02-shared-nolocal',
    '02-shared-qos0-v5',
    '02-subhier-crash',
    '02-subpub-b2c-topic-alias',
    '02-subpub-qos0-long-topic',
    '02-subpub-qos0-retain-as-publish',
    '02-subpub-qos0-send-retain',
    '02-subpub-qos0-subscription-id',
    '02-subpub-qos0-topic-alias-unknown',
    '02-subpub-qos0-topic-alias',
    '02-subpub-qos0',
    '02-subpub-qos1-bad-pubcomp',
    '02-subpub-qos1-bad-pubrec',
    '02-subpub-qos1-message-expiry-retain',
    '02-subpub-qos1-message-expiry-will',
    '02-subpub-qos1-message-expiry',
    '02-subpub-qos1-nolocal',
    '02-subpub-qos1',
    '02-subpub-qos2-1322',
    '02-subpub-qos2-bad-puback-1',
    '02-subpub-qos2-bad-puback-2',
    '02-subpub-qos2-bad-pubcomp',
    '02-subpub-qos2-pubrec-error',
    '02-subpub-qos2-receive-maximum-1',
    '02-subpub-qos2-receive-maximum-2',
    '02-subpub-qos2',
    '02-subscribe-dollar-v5',
    '02-subscribe-invalid-utf8',
    '02-subscribe-long-topic',
    '02-subscribe-persistence-flipflop',
    '02-subscribe-qos0',
    '02-subscribe-qos1',
    '02-subscribe-qos2',
    '02-unsubscribe-invalid-no-topic',
    '02-unsubscribe-qos0',
    '02-unsubscribe-qos1',
    '02-unsubscribe-qos2-multiple',
    '02-unsubscribe-qos2',

    ##'03-pattern-matching',
    '03-publish-b2c-disconnect-qos1',
    '03-publish-b2c-disconnect-qos2',
    '03-publish-b2c-qos1-len',
    '03-publish-b2c-qos2-len',
    '03-publish-c2b-disconnect-qos2',
    '03-publish-c2b-qos2-len',
    '03-publish-dollar-v5',
    '03-publish-dollar',
    '03-publish-invalid-utf8',
    '03-publish-long-topic',
    '03-publish-qos1-no-subscribers-v5',
    '03-publish-qos1',
    '03-publish-qos2',

    '04-retain-qos0-clear',
    '04-retain-qos0-fresh',
    '04-retain-qos0-repeated',
    '04-retain-qos0',
    '04-retain-qos1-qos0',

    '05-clean-session-qos1',
    '05-session-expiry-v5',

    '06-bridge-no-local',

    '07-will-delay',
    '07-will-delay-reconnect',
    '07-will-delay-recover',
    '07-will-delay-session-expiry',
    '07-will-delay-session-expiry2',
    '07-will-disconnect-with-will',
    '07-will-invalid-utf8',
    '07-will-no-flag',
    '07-will-null',
    '07-will-null-topic',
    '07-will-properties',
    '07-will-qos0',
    '07-will-reconnect-1273',
    '07-will-takeover',

    '09-auth-bad-method',
    '09-extended-auth-unsupported',

    '12-prop-assigned-client-identifier',
    '12-prop-maximum-packet-size-connect',
    '12-prop-maximum-packet-size-publish',
    '12-prop-maximum-packet-size-publish-qos1',
    '12-prop-maximum-packet-size-publish-qos2',
    '12-prop-response-topic',
    '12-prop-response-topic-correlation-data',
    '12-prop-session-expiry-invalid',
    '12-prop-subpub-content-type',
    '12-prop-subpub-payload-format',
    '12-prop-topic-alias-invalid',

    '13-malformed-subscribe-v5',
    '13-malformed-unsubscribe-v5',
    ]

def single_test(name):
    start_time = time.time()
    try:
        mod = importlib.import_module(name)
    except ModuleNotFoundError:
        print("------ : \033[31m%s\033[0m test not found" % (name))
        return 1

    rc = mod.all_tests()
    runtime = time.time() - start_time
    if rc:
        print("%0.3fs : \033[31m%s\033[0m" % (runtime, name))
    else:
        print("%0.3fs : \033[32m%s\033[0m" % (runtime, name))
    return rc


port = mosq_test.get_port()
broker = mosq_test.start_broker(filename=os.path.basename(__file__), port=port, nolog=True)

rc = 0
try:
    # FIXME - use Queue instead to limit max threads
    threads = []
    for test in tests:
        t = threading.Thread(target=single_test, args=(test,), name=test)
        threads.append(t)
        t.start()

    # FIXME - return code
    for t in threads:
        t.join()

finally:
    broker.terminate()
    if mosq_test.wait_for_subprocess(broker):
        print("broker not terminated")
        if rc == 0: rc=1
    (stdo, stde) = broker.communicate()
    if rc:
        print(stde.decode('utf-8'))
