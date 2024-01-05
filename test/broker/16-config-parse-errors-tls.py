#!/usr/bin/env python3

# Test whether config parse errors are handled

from mosq_test_helper import *

conf_file = os.path.basename(__file__).replace('.py', '.conf')
port = mosq_test.get_port()

do_test_broker_failure(conf_file, ["bridge_cafile string"], port, 3) # Missing bridge config
do_test_broker_failure(conf_file, ["bridge_alpn string"], port, 3) # Missing bridge config
do_test_broker_failure(conf_file, ["bridge_ciphers string"], port, 3) # Missing bridge config
do_test_broker_failure(conf_file, ["bridge_ciphers_tls1.3 string"], port, 3) # Missing bridge config
do_test_broker_failure(conf_file, ["bridge_capath string"], port, 3) # Missing bridge config
do_test_broker_failure(conf_file, ["bridge_certfile string"], port, 3) # Missing bridge config
do_test_broker_failure(conf_file, ["bridge_keyfile string"], port, 3) # Missing bridge config
do_test_broker_failure(conf_file, ["bridge_tls_version string"], port, 3) # Missing bridge config

do_test_broker_failure(conf_file, [f"listener {port}","certfile"], port, 3) # empty certfile
do_test_broker_failure(conf_file, [f"listener {port}","keyfile"], port, 3) # empty keyfile

do_test_broker_failure(conf_file, [f"listener {port}","certfile ./16-config-parse-errors.py","keyfile ../ssl/server.key"], port, 1) # invalid certfile
do_test_broker_failure(conf_file, [f"listener {port}","certfile ../ssl/server.crt","keyfile ./16-config-parse-errors.py"], port, 1) # invalid keyfile
do_test_broker_failure(conf_file, [f"listener {port}","certfile ../ssl/server.crt","keyfile ../ssl/client.key"], port, 1) # mismatched certfile / keyfile

do_test_broker_failure(conf_file, [f"listener {port}","certfile ../ssl/server.crt","keyfile ../ssl/server.key","tls_version invalid"], port, 1) # invalid tls_version

do_test_broker_failure(conf_file, [f"listener {port}","certfile ../ssl/server.crt","keyfile ../ssl/server.key","crlfile invalid"], port, 1) # missing crl file
do_test_broker_failure(conf_file, [f"listener {port}","certfile ../ssl/server.crt","keyfile ../ssl/server.key","dhparamfile invalid"], port, 1) # missing dh param file
do_test_broker_failure(conf_file, [f"listener {port}","certfile ../ssl/server.crt","keyfile ../ssl/server.key","dhparamfile ./16-config-parse-errors.py"], port, 1) # invalid dh param file
do_test_broker_failure(conf_file, [f"listener {port}","certfile ../ssl/server.crt","keyfile ../ssl/server.key","ciphers invalid"], port, 1) # invalid ciphers
do_test_broker_failure(conf_file, [f"listener {port}","certfile ../ssl/server.crt","keyfile ../ssl/server.key","ciphers_tls1.3 invalid"], port, 1) # invalid ciphers_tls1.3

exit(0)
