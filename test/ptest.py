#!/usr/bin/env python3

import subprocess
import time
import sys

def next_test(tests, ports):
    if len(tests) == 0 or len(ports) == 0:
        return

    test = tests.pop()
    proc_ports = ()

    if len(ports) < test[0]:
        tests.insert(0, test)
        return None
    else:
        if isinstance(test[1], (list,)):
            args = test[1]
        else:
            args = [test[1]]

        try:
            args.append(test[2])
        except IndexError:
            pass

        for i in range(0, test[0]):
            proc_port = ports.pop()
            proc_ports = proc_ports + (proc_port,)
            args.append(str(proc_port))

        proc = subprocess.Popen(args)
        proc.start_time = time.time()
        proc.mosq_port = proc_ports
        return proc


def run_tests(tests, minport=1888, max_running=20):
    ports = list(range(minport, minport+max_running+1))
    start_time = time.time()
    passed = 0
    failed = 0

    failed_tests = []

    running_tests = []
    while len(tests) > 0 or len(running_tests) > 0:
        if len(running_tests) <= max_running:
            t = next_test(tests, ports)
            if t is None:
                time.sleep(0.1)
            else:
                running_tests.append(t)

        for t in running_tests:
            t.poll()
            if t.returncode is not None:
                running_tests.remove(t)
                if isinstance(t.mosq_port, tuple):
                    for portret in t.mosq_port:
                        ports.append(portret)
                else:
                    ports.append(t.mosq_port)
                t.terminate()
                t.wait()
                runtime = time.time() - t.start_time
                #(stdo, stde) = t.communicate()
                if t.returncode == 1:
                    print("%0.3fs : \033[31m%s\033[0m" % (runtime, t.args[0]))
                    failed = failed + 1
                    failed_tests.append(t.args[0])
                else:
                    passed = passed + 1
                    print("%0.3fs : \033[32m%s\033[0m" % (runtime, t.args[0]))

    print("Passed: %d\nFailed: %d\nTotal: %d\nTotal time: %0.2f" % (passed, failed, passed+failed, time.time()-start_time))
    if failed > 0:
        print("Failing tests:")
        failed_tests.sort()
        for f in failed_tests:
            print(f)
        sys.exit(1)

