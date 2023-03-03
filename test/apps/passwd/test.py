#!/usr/bin/env python3

import mosq_test_helper
import pathlib
import ptest

tests = []

for test_file in pathlib.Path('.').glob('passwd-*.py'):
    tests.append((1, test_file.resolve()))

ptest.run_tests(tests)
