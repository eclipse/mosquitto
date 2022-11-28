#!/usr/bin/env python3

# Test parsing of command line args and errors. Does not test arg functionality.

from mosq_test_helper import *

def do_test(args, rc_expected, response=None, input=None):
    proc = subprocess.run([mosq_test.get_build_root()+"/apps/mosquitto_passwd/mosquitto_passwd"]
                    + args,
                    capture_output=True, encoding='utf-8', timeout=2, input=input)

    if response is not None:
        if proc.stderr != response:
            print(len(proc.stderr))
            print(len(response))
            raise ValueError(proc.stderr)

    if proc.returncode != rc_expected:
        print(proc.returncode)
        raise ValueError(args)

do_test([], 1) # For the usage message
do_test(["-H"], 1, response="Error: -H argument given but not enough other arguments.\n")
do_test(["-H", "nohash"], 1, response="Error: Unknown hash type 'nohash'\n")
do_test(["-I"], 1, response="Error: -I argument given but not enough other arguments.\n")
do_test(["-I", "0"], 1, response="Error: Number of iterations must be > 0.\n")
do_test(["-c", "-D"], 1, response="Error: -c and -D cannot be used together.\n")
do_test(["-c", "-U"], 1, response="Error: -c and -U cannot be used together.\n")
do_test(["-U", "-D"], 1, response="Error: -D and -U cannot be used together.\n")
do_test(["-b", "-D"], 1, response="Error: -b and -D cannot be used together.\n")
do_test(["-c", "-b"], 1, response="Error: -c argument given but password file, username, or password missing.\n")
do_test(["-c"], 1, response="Error: -c argument given but password file or username missing.\n")
do_test(["-D"], 1, response="Error: -D argument given but password file or username missing.\n")
do_test(["-U"], 1, response="Error: -U argument given but password file missing.\n")
do_test(["-D", "pwfile", "bad-username:"], 1, response="Error: Username must not contain the ':' character.\n")
do_test(["-D", "pwfile", "bad-username\n"], 1, response="Error: Username must not contain control characters.\n")
do_test(["-D", "pwfile", "a"*65536], 1, response="Error: Username must be less than 65536 characters long.\n")

do_test(["-c", "file", "username"], 2, response="Error: Passwords do not match.\n", input="not\nmatching\n")

exit(0)
