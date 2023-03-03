#!/usr/bin/env python3

# Test whether config parse errors are handled

from mosq_test_helper import *

conf_file = os.path.basename(__file__).replace('.py', '.conf')

broker = mosq_test.start_broker(conf_file, check_port=False)
mosq_test.wait_for_subprocess(broker)


assert(broker.returncode == 3)
(_, stde) = broker.communicate()
error_message = stde.decode('utf-8')
if not error_message.endswith(f"Error: Unable to open config file '{conf_file}'.\n"):
    print(f"Got wrong error message: '{error_message}'")
    exit(1)

exit(0)
