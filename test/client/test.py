#!/usr/bin/env python3

import sys
sys.path.insert(0, "..")
import ptest

tests = [
    #(ports required, 'path'),
    (1, './02-subscribe-argv-errors-tls-psk.py'),
    (1, './02-subscribe-argv-errors-tls.py'),
    (1, './02-subscribe-argv-errors-without-tls.py'),
    (1, './02-subscribe-env.py'),
    (1, './02-subscribe-filter-out.py'),
    (1, './02-subscribe-format.py'),
	(1, './02-subscribe-format-json-qos0.py'),
	(1, './02-subscribe-format-json-qos1.py'),
    (1, './02-subscribe-format-json-properties.py'),
    (1, './02-subscribe-format-json-retain.py'),
    (1, './02-subscribe-null.py'),
    (1, './02-subscribe-qos1.py'),
    (2, './02-subscribe-qos1-ws.py'),
    (1, './02-subscribe-retain-handling.py'),
    (1, './02-subscribe-verbose.py'),

    (1, './03-publish-argv-errors-tls-psk.py'),
    (1, './03-publish-argv-errors-tls.py'),
    (1, './03-publish-argv-errors-without-tls.py'),
    (1, './03-publish-env.py'),
    (1, './03-publish-file-empty.py'),
    (1, './03-publish-file.py'),
    (1, './03-publish-options-file.py'),
    (1, './03-publish-qos0-empty.py'),
    (1, './03-publish-qos1-properties.py'),
    (1, './03-publish-qos1.py'),
    (1, "./03-publish-qos1-unix.py"),
    (2, './03-publish-qos1-ws.py'),
    (2, './03-publish-qos1-ws-large.py'),
    (1, './03-publish-repeat.py'),
    (1, './03-publish-url.py'),
    (1, './03-publish-tls.py'),

    (2, './03-publish-socks.py'),
    (2, './03-publish-socks-auth-failed.py'),
    (2, './03-publish-socks-no-auth.py'),
    (1, './03-publish-stdin-file.py'),
    (1, './03-publish-stdin-line.py'),

    (1, './04-rr-argv-errors-tls-psk.py'),
    (1, './04-rr-argv-errors-tls.py'),
    (1, './04-rr-argv-errors-without-tls.py'),
    (1, './04-rr-env.py'),
    (1, './04-rr-qos1.py'),
    (2, './04-rr-qos1-ws.py'),
    (1, './04-rr-retain-handling.py'),
    ]

if __name__ == "__main__":
    test = ptest.PTest()
    test.run_tests(tests)
