#!/usr/bin/python3

build_variants = [
    #'WITH_ARGON2',
    'WITH_ADNS',
    'WITH_APPS',
    'WITH_BROKER',
    'WITH_CLIENTS',
    'INC_BRIDGE_SUPPORT',
    'WITH_CONTROL',
    'WITH_CTRL_SHELL',
    'WITH_DLT',
    'WITH_HTTP_API',
    'WITH_LIB_CPP',
    'WITH_LTO',
    'INC_MEMTRACK',
    'WITH_OLD_KEEPALIVE',
    'WITH_PERSISTENCE',
    'WITH_PLUGINS',
    'WITH_PLUGIN_ACL_FILE',
    'WITH_PLUGIN_DYNAMIC_SECURITY',
    'WITH_PLUGIN_EXAMPLES',
    'WITH_PLUGIN_PASSWORD_FILE',
    'WITH_PLUGIN_PERSIST_SQLITE',
    'WITH_PLUGIN_SPARKPLUG_AWARE',
    #'WITH_SHARED_LIBRARIES',
    'WITH_SOCKS',
    'WITH_SRV',
    'WITH_STATIC_LIBRARIES',
    'WITH_SYSTEMD',
    'WITH_SYS_TREE',
    'WITH_THREADING',
    'WITH_TLS',
    'WITH_TLS_PSK',
    'WITH_UNIX_SOCKETS',
    'WITH_WEBSOCKETS',
    'WITH_WEBSOCKETS_BUILTIN',
    'WITH_XTREPORT',
]

special_variants = [
    'WITH_BUNDLED_DEPS',
    'WITH_COVERAGE',
]


import os
import random
import shutil
import subprocess
import sys
import time

class Duration():
    def __init__(self, label):
        self.label = label

    def __enter__(self):
        self.start = time.time()
        print(self.label, end="")
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        duration = time.time() - self.start
        print(f" {duration:.2f}s")


def build_test(msg, run_tests, opts):
    try:
        shutil.rmtree("build")
    except FileNotFoundError:
        pass
    print("%s: %s" % (msg, str(opts)))

    # CMake
    with Duration("   cmake"):
        env = os.environ.copy()
        env['CC'] = "ccache gcc"
        env['CXX'] = "ccache g++"
        args = ["cmake", "-DCMAKE_BUILD_TYPE=Debug", "-S", ".", "-B", "build", "-G", "Ninja"] + opts
        proc = subprocess.run(args, stdout=subprocess.DEVNULL, env=env)
        if proc.returncode != 0:
            raise RuntimeError("CMAKE FAILED: %s" % (' '.join(args)))

    # Build
    with Duration("   build"):
        args = ["cmake", "--build", "build", "--config", "Debug"]
        proc = subprocess.run(args, stdout=subprocess.DEVNULL, env=env)
        if proc.returncode != 0:
            raise RuntimeError("BUILD FAILED: %s" % (' '.join(args)))

    if run_tests:
        # Test
        with Duration("   test"):
            args = ["ctest", "-j20", "--resource-spec-file", "../test/resource.json", "--test-dir", "build", "--output-on-failure", "--repeat", "until-pass:5"]
            proc = subprocess.run(args, stdout=subprocess.DEVNULL, env=env)
            if proc.returncode != 0:
                raise RuntimeError("TEST FAILED: %s" % (' '.join(args)))

def report(res, opts):
    with open("RESULTS", "at") as f:
        f.write(f"{res} {opts}\n")

def simple_tests(run_tests):
    failures = []
    for bv in build_variants:
        for enabled in ["ON", "OFF"]:
            opts = f"-D{bv}={enabled}"
            try:
                build_test("SIMPLE BUILD", run_tests, [opts])
                report("SUCCESS",  opts)
            except RuntimeError:
                report("FAILURE",  opts)
                failures.append(opts)
    print(failures)


def random_tests(count, run_tests):
    for i in range(1, count):
        opts = []
        for bv in build_variants:
            opts.append(f"-D{bv}={random.choice(['ON', 'OFF'])}")

        build_test("RANDOM BUILD", run_tests, opts)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--tests":
        run_tests = True
    else:
        run_tests = False
    simple_tests(run_tests)
    #random_tests(2, run_tests)
