#!/usr/bin/python3

build_variants = [
    'WITH_ADNS',
    'WITH_BRIDGE',
    'WITH_CJSON',
    'WITH_DOCS',
    'WITH_EC',
    'WITH_EPOLL',
    'WITH_MEMORY_TRACKING',
    'WITH_PERSISTENCE',
    'WITH_SHARED_LIBRARIES',
    'WITH_SOCKS',
    'WITH_SRV',
    'WITH_STATIC_LIBRARIES',
    'WITH_STRIP',
    'WITH_SYSTEMD',
    'WITH_SYS_TREE',
    'WITH_THREADING',
    'WITH_TLS',
    'WITH_TLS_PSK',
    'WITH_UNIX_SOCKETS',
    'WITH_WEBSOCKETS',
    'WITH_WRAP',
    'WITH_XTREPORT',
]

special_variants = [
    'WITH_BUNDLED_DEPS',
    'WITH_COVERAGE',
]


import os
import random
import subprocess

def run_test(msg, opts):
    subprocess.run(["make", "clean"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print("%s: %s" % (msg, str(opts)))
    args = ["make", "-j%d" % (os.cpu_count())] + opts
    proc = subprocess.run(args, stdout=subprocess.DEVNULL)
    if proc.returncode != 0:
        raise RuntimeError("BUILD FAILED: %s" % (' '.join(args)))

def simple_tests():
    for bv in build_variants:
        for enabled in ["yes", "no"]:
            opts = "%s=%s" % (bv, enabled)
            run_test("SIMPLE BUILD", [opts])

def random_tests(count=10):
    for i in range(1, count):
        opts = []
        for bv in build_variants:
            opts.append("%s=%s" % (bv, random.choice(["yes", "no"])))

        run_test("RANDOM BUILD", opts)


if __name__ == "__main__":
    simple_tests()
    random_tests(100)
