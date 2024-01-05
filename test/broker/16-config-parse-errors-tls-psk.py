#!/usr/bin/env python3

# Test whether config parse errors are handled

from mosq_test_helper import *
port = mosq_test.get_port()

conf_file = os.path.basename(__file__).replace('.py', '.conf')

do_test_broker_failure(conf_file, ["bridge_psk string"], port, 3, "Error: The 'bridge_psk' option requires a bridge to be defined first.")
do_test_broker_failure(conf_file, ["bridge_identity string"], port, 3, "Error: The 'bridge_identity' option requires a bridge to be defined first.")

bridge_config=["connection invalid-psk", "address localhost", "topic dummy-topic"]
do_test_broker_failure(conf_file, bridge_config+ ["bridge_psk"], port, 3, "Error: Empty 'bridge_psk' value in configuration.") # Empty bridge_psk in bridge config
do_test_broker_failure(conf_file, bridge_config+ ["bridge_identity"], port, 3, "Error: Empty 'bridge_identity' value in configuration.") # Empty bridge_identity in bridge config
do_test_broker_failure(conf_file, bridge_config+ ["bridge_psk my_psk"], port, 3, "Error: Invalid bridge configuration: missing bridge_identity.") # Missing bridge_identity in bridge config
do_test_broker_failure(conf_file, bridge_config+ ["bridge_identity my_identity"], port, 3, "Error: Invalid bridge configuration: missing bridge_psk.") # Missing bridge_psk in bridge config


exit(0)
