#!/usr/bin/env python3

# Test whether config parse errors are handled

from mosq_test_helper import *

mosq_test.require_features(["WITH_TLS"])

conf_file = os.path.basename(__file__).replace('.py', '.conf')
port = mosq_test.get_port()

if mosq_test.check_features(["INC_BRIDGE_SUPPORT"]):
    do_test_broker_failure(conf_file, ["bridge_cafile string"], port, 3) # Missing bridge config
    do_test_broker_failure(conf_file, ["bridge_alpn string"], port, 3) # Missing bridge config
    do_test_broker_failure(conf_file, ["bridge_ciphers string"], port, 3) # Missing bridge config
    do_test_broker_failure(conf_file, ["bridge_ciphers_tls1.3 string"], port, 3) # Missing bridge config
    do_test_broker_failure(conf_file, ["bridge_capath string"], port, 3) # Missing bridge config
    do_test_broker_failure(conf_file, ["bridge_certfile string"], port, 3) # Missing bridge config
    do_test_broker_failure(conf_file, ["bridge_keyfile string"], port, 3) # Missing bridge config
    do_test_broker_failure(conf_file, ["bridge_tls_version string"], port, 3) # Missing bridge config
    do_test_broker_failure(conf_file, ["bridge_insecure true"], port, 3, "Error: The 'bridge_insecure' option requires a bridge to be defined first.") # Missing bridge config

do_test_broker_failure(conf_file, [f"listener {port}","certfile"], port, 3) # empty certfile
do_test_broker_failure(conf_file, [f"listener {port}","keyfile"], port, 3) # empty keyfile

do_test_broker_failure(conf_file, [f"listener {port}","certfile ./16-config-parse-errors.py","keyfile ../ssl/server.key"], port, 1, with_test_config=False) # invalid certfile
do_test_broker_failure(conf_file, [f"listener {port}","certfile ../ssl/server.crt","keyfile ./16-config-parse-errors.py"], port, 1, with_test_config=False) # invalid keyfile
do_test_broker_failure(conf_file, [f"listener {port}","certfile ../ssl/server.crt","keyfile ../ssl/client.key"], port, 1, with_test_config=False) # mismatched certfile / keyfile

do_test_broker_failure(conf_file, [f"listener {port}","certfile ../ssl/server.crt","keyfile ../ssl/server.key","tls_version invalid"], port, 1, with_test_config=False) # invalid tls_version

do_test_broker_failure(conf_file, [f"listener {port}","certfile ../ssl/server.crt","keyfile ../ssl/server.key","crlfile invalid"], port, 1, with_test_config=False) # missing crl file
do_test_broker_failure(conf_file, [f"listener {port}","certfile ../ssl/server.crt","keyfile ../ssl/server.key","ciphers invalid"], port, 1, with_test_config=False) # invalid ciphers
do_test_broker_failure(conf_file, [f"listener {port}","certfile ../ssl/server.crt","keyfile ../ssl/server.key","ciphers_tls1.3 invalid"], port, 1, with_test_config=False) # invalid ciphers_tls1.3

exit(0)
