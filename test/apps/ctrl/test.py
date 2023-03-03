#!/usr/bin/env python3

import mosq_test_helper
import pathlib
import ptest

tests = [
    (0, './ctrl-args.py'),
    (2, './ctrl-broker.py'),
    (2, './ctrl-dynsec.py')
]

ptest.run_tests(tests)
