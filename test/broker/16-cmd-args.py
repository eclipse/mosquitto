#!/usr/bin/env python3

# Test whether command line args are handled

from mosq_test_helper import *
import platform

port = mosq_test.get_port()

do_test_broker_failure("", [], port, cmd_args=["-h"], rc_expected=0, stdout_entry="Usage: mosquitto [-c config_file] [-d] [-h] [-p port] [-v]")
do_test_broker_failure("", [], port, cmd_args=["-p", "0"], rc_expected=3, error_log_entry="Error: Invalid port specified (0).") # Port invalid
if platform.system() != 'Windows':
    do_test_broker_failure("", [], 1, cmd_args=[], rc_expected=1, error_log_entry="Error: Permission denied") # Port in privileged range
do_test_broker_failure("", [], port, cmd_args=["-p", "65536"], rc_expected=3, error_log_entry="Error: Invalid port specified (65536).") # Port invalid
do_test_broker_failure("", [], port, cmd_args=["-p"], rc_expected=3, error_log_entry="Error: -p argument given, but no port specified.") # Missing port
do_test_broker_failure("", [], port, cmd_args=["-c"], rc_expected=3, error_log_entry="Error: -c argument given, but no config file specified.") # Missing config
if mosq_test.check_features(["WITH_TLS"]):
    do_test_broker_failure("", [], port, cmd_args=["--tls-keylog"], rc_expected=3, error_log_entry="Error: --tls-keylog argument given, but no file specified.") # Missing filename
do_test_broker_failure("", [], port, cmd_args=["--unknown"], rc_expected=3, error_log_entry="Error: Unknown option '--unknown'.") # Unknown option

exit(0)
