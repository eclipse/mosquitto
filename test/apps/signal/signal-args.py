#!/usr/bin/env python3

# Test parsing of command line args and errors. Does not test arg functionality.

from mosq_test_helper import *

import os
import platform
import signal

def do_test(args, rc_expected, response=None, input=None, sig=None):
    if sig is not None:
        signal.signal(sig, signal.SIG_IGN)

    try:
        proc = subprocess.run([mosq_paths.mosquitto_signal]
                        + args,
                        capture_output=True, encoding='utf-8', timeout=2, input=input)
    except KeyboardInterrupt:
        if sig == signal.SIGINT:
            pass

    if response is not None:
        if response not in proc.stderr:
            print(len(proc.stderr))
            print(len(response))
            raise ValueError(proc.stderr)

    if proc.returncode != rc_expected:
        print(proc.returncode)
        raise ValueError(args)

    if sig is not None:
        signal.signal(sig, signal.SIG_DFL)


if platform.system() == 'Windows':
    sighup = None
    sigint = None
    sigusr1 = None
    sigusr2 = None
    sigrtmin = None
else:
    sighup = signal.SIGHUP
    sigint = signal.SIGINT
    sigusr1 = signal.SIGUSR1
    sigusr2 = signal.SIGUSR2
    try:
        sigrtmin = signal.SIGRTMIN
    except AttributeError:
        sigrtmin = None

pid = os.getpid()

do_test([], 1) # For the usage message
do_test(["--help"], 1)
do_test(["--invalid"], 1, response="Error: One of -a or -p must be used.")
do_test(["-p"], 1, response="Error: -p argument given but process ID missing.")
do_test(["-p", "0"], 1, response="Error: Process ID must be >0.")
do_test(["-p", str(pid)], 1, response="Error: No signal given.")
do_test(["-a"], 1, response="Error: No signal given.")
do_test(["-p", str(pid), "invalid"], 1, response="Error: Unknown signal 'invalid'.")
do_test(["-p", str(pid), "config-reload"], 0, sig=sighup)
do_test(["-p", str(pid), "log-rotate"], 0, sig=sighup)
do_test(["-p", str(pid), "shutdown"], 0, sig=sigint)
do_test(["-p", str(pid), "tree-print"], 0, sig=sigusr2)
do_test(["-p", str(pid), "xtreport"], 0, sig=sigrtmin)
do_test(["-a", "config-reload"], 0)
exit(0)
