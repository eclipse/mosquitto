#!/usr/bin/env python3

# Test whether config parse errors are handled

from mosq_test_helper import *

conf_file = os.path.basename(__file__).replace('.py', '.conf')
port = mosq_test.get_port()

do_test_broker_failure(conf_file, ["unknown_option unknown"], 3, "Error: Unknown configuration variable 'unknown_option'")
do_test_broker_failure(conf_file, ["user"], 3, "Error: Empty 'user' value in configuration.") # Empty string, no space
do_test_broker_failure(conf_file, ["user "], 3, "Error: Empty 'user' value in configuration.") # Empty string, single space
do_test_broker_failure(conf_file, ["user  "], 3, "Error: Empty 'user' value in configuration.") # Empty string, double space
do_test_broker_failure(conf_file, ["pid_file /tmp/pid","pid_file /tmp/pid"], 3, "Error: Duplicate 'pid_file' value in configuration.") # Duplicate string
do_test_broker_failure(conf_file, ["memory_limit"], 3, "Empty 'memory_limit' value in configuration.") # Empty ssize_t
do_test_broker_failure(conf_file, ["accept_protocol_versions 3"], 3, "Error: The 'accept_protocol_versions' option requires a listener to be defined first.") # Missing listener
do_test_broker_failure(conf_file, [f"listener {port}","accept_protocol_versions"], 3, "Error: Empty 'accept_protocol_versions' value in configuration.") # Empty value
do_test_broker_failure(conf_file, ["allow_anonymous"], 3, "Error: Empty 'allow_anonymous' value in configuration.") # Empty bool
do_test_broker_failure(conf_file, ["allow_anonymous falst"], 3, "Error: Invalid 'allow_anonymous' value (falst).") # Invalid bool

do_test_broker_failure(conf_file, ["autosave_interval"], 3, "Error: Empty 'autosave_interval' value in configuration.") # Empty int
#do_test_broker_failure(conf_file, ["autosave_interval string"], 3, "bla") # Invalid int
do_test_broker_failure(conf_file, ["listener"], 3, "Error: Empty 'listener port' value in configuration.") # Empty listener
do_test_broker_failure(conf_file, ["mount_point test/"], 3, "Error: The 'mount_point' option requires a listener to be defined first.") # Missing listener config
do_test_broker_failure(conf_file, [f"listener {port}","mount_point test/+/"], 3, "Error: Invalid 'mount_point' value (test/+/). Does it contain a wildcard character?") # Wildcard in mount point.
do_test_broker_failure(conf_file, [f"listener {port}","protocol"], 3, "Error: Empty 'protocol' value in configuration.") # Empty proto
do_test_broker_failure(conf_file, [f"listener {port}","protocol test"], 3, "Error: Invalid 'protocol' value (test).") # Invalid proto
do_test_broker_failure(conf_file, [f"listener {port}","accept_protocol_versions"], 3, "Error: Empty 'accept_protocol_versions' value in configuration.")
do_test_broker_failure(conf_file, ["admin_listeners_only"], 3, "Error: Empty 'admin_listeners_only' value in configuration.") # empty balue
do_test_broker_failure(conf_file, ["admin_listeners_only bla"], 3, "Error: Invalid 'admin_listeners_only' value (bla).") # Invalid bool value
do_test_broker_failure(conf_file, ["admin_listeners_only 4711"], 3, "Error: Invalid 'admin_listeners_only' value (4711).") # Invalid bool value

do_test_broker_failure(conf_file, ["plugin_opt_inval string"], 3, "Error: The 'plugin_opt_inval' option requires plugin/global_plugin/plugin_load to be defined first.") # plugin_opt_ without plugin
do_test_broker_failure(conf_file, ["plugin c/auth_plugin.so","plugin_opt_ string"], 3, "Error: Invalid 'plugin_opt_' config option.") # Incomplete plugin_opt_
do_test_broker_failure(conf_file, ["plugin c/auth_plugin.so","plugin_opt_test"], 3, "Error: Empty 'test' value in configuration.") # Empty plugin_opt_

do_test_broker_failure(conf_file, ["bridge_attempt_unsubscribe true"], 3, "Error: The 'bridge_attempt_unsubscribe' option requires a bridge to be defined first.") # Missing bridge config
do_test_broker_failure(conf_file, ["bridge_bind_address string"], 3, "Error: The 'bridge_bind_address' option requires a bridge to be defined first.") # Missing bridge config
do_test_broker_failure(conf_file, ["bridge_insecure true"], 3, "Error: The 'bridge_insecure' option requires a bridge to be defined first.") # Missing bridge config
#do_test_broker_failure(conf_file, ["bridge_require_oscp true"], 3, "Error: The 'bridge_require_oscp' option requires a bridge to be defined first.") # Missing bridge config
do_test_broker_failure(conf_file, ["bridge_max_packet_size 1000"], 3, "Error: The 'bridge_max_packet_size' option requires a bridge to be defined first.") # Missing bridge config
do_test_broker_failure(conf_file, ["bridge_max_topic_alias 1000"], 3, "Error: The 'bridge_max_topic_alias' option requires a bridge to be defined first.") # Missing bridge config
do_test_broker_failure(conf_file, ["bridge_outgoing_retain false"], 3, "Error: The 'bridge_outgoing_retain' option requires a bridge to be defined first.") # Missing bridge config
do_test_broker_failure(conf_file, ["bridge_fatal_sub_errors false"], 3, "Error: The 'bridge_fatal_sub_errors' option requires a bridge to be defined first.") # Missing bridge config
do_test_broker_failure(conf_file, ["bridge_protocol_version string"], 3, "Error: The 'bridge_protocol_version' option requires a bridge to be defined first.") # Missing bridge config
do_test_broker_failure(conf_file, ["bridge_receive_maximum 10"], 3, "Error: The 'bridge_receive_maximum' option requires a bridge to be defined first.") # Missing bridge config
do_test_broker_failure(conf_file, ["bridge_reload_type string"], 3, "Error: The 'bridge_reload_type' option requires a bridge to be defined first.") # Missing bridge config
do_test_broker_failure(conf_file, ["bridge_session_expiry_interval 10000"], 3, "Error: The 'bridge_session_expiry_interval' option requires a bridge to be defined first.") # Missing bridge config
do_test_broker_failure(conf_file, ["bridge_tcp_keepalive 10000"], 3, "Error: The 'bridge_tcp_keepalive' option requires a bridge to be defined first.") # Missing bridge config
do_test_broker_failure(conf_file, ["bridge_tcp_user_timeout 10000"], 3, "Error: The 'bridge_tcp_user_timeout' option requires a bridge to be defined first.") # Missing bridge config
do_test_broker_failure(conf_file, ["local_clientid str"], 3, "Error: The 'local_clientid' option requires a bridge to be defined first.") # Missing bridge config
do_test_broker_failure(conf_file, ["local_password str"], 3, "Error: The 'local_password' option requires a bridge to be defined first.") # Missing bridge config
do_test_broker_failure(conf_file, ["local_username str"], 3, "Error: The 'local_username' option requires a bridge to be defined first.") # Missing bridge config
do_test_broker_failure(conf_file, ["notifications true"], 3, "Error: The 'notifications' option requires a bridge to be defined first.") # Missing bridge config
do_test_broker_failure(conf_file, ["notifications_local_only true"], 3, "Error: The 'notifications_local_only' option requires a bridge to be defined first.") # Missing bridge config
do_test_broker_failure(conf_file, ["notification_topic true"], 3, "Error: The 'notification_topic' option requires a bridge to be defined first.") # Missing bridge config
do_test_broker_failure(conf_file, ["password pw"], 3, "Error: The 'password' option requires a bridge to be defined first.") # Missing bridge config
do_test_broker_failure(conf_file, ["remote_password pw"], 3, "Error: The 'remote_password' option requires a bridge to be defined first.") # Missing bridge config
do_test_broker_failure(conf_file, ["restart_timeout 10"], 3, "Error: The 'restart_timeout' option requires a bridge to be defined first.") # Missing bridge config
do_test_broker_failure(conf_file, ["round_robin true"], 3, "Error: The 'round_robin' option requires a bridge to be defined first.") # Missing bridge config
do_test_broker_failure(conf_file, ["start_type lazy"], 3, "Error: The 'start_type' option requires a bridge to be defined first.") # Missing bridge config
do_test_broker_failure(conf_file, ["threshold 10"], 3, "Error: The 'threshold' option requires a bridge to be defined first.") # Missing bridge config
do_test_broker_failure(conf_file, ["topic topic/10"], 3, "Error: The 'topic' option requires a bridge to be defined first.") # Missing bridge config
do_test_broker_failure(conf_file, ["try_private true"], 3, "Error: The 'try_private' option requires a bridge to be defined first.") # Missing bridge config
do_test_broker_failure(conf_file, ["username un"], 3, "Error: The 'username' option requires a bridge to be defined first.") # Missing bridge config

do_test_broker_failure(conf_file, ["maximum_qos 3"], 3, "Error: 'max_qos' must be between 0 and 2 inclusive.") # Invalid maximum qos
do_test_broker_failure(conf_file, ["maximum_qos -1"], 3, "Error: 'max_qos' must be between 0 and 2 inclusive.") # Invalid maximum qos

do_test_broker_failure(conf_file, ["max_inflight_messages 65536"], 3, "Error: 'max_inflight_messages' must be <= 65535.") # Invalid value

do_test_broker_failure(conf_file, ["max_keepalive 65536"], 3, "Error: Invalid 'max_keepalive' value (65536).") # Invalid value
do_test_broker_failure(conf_file, ["max_keepalive -1"], 3, "Error: Invalid 'max_keepalive' value (-1).") # Invalid value

do_test_broker_failure(conf_file, [f"listener {port}", "max_topic_alias 65536"], 3, "Error: Invalid 'max_topic_alias' value in configuration.") # Invalid value
do_test_broker_failure(conf_file, [f"listener {port}", "max_topic_alias -1"], 3, "Error: Invalid 'max_topic_alias' value in configuration.") # Invalid value
do_test_broker_failure(conf_file, [f"listener {port}", "max_topic_alias_broker 65536"], 3, "Error: Invalid 'max_topic_alias_broker' value in configuration.") # Invalid value
do_test_broker_failure(conf_file, [f"listener {port}", "max_topic_alias_broker -1"], 3, "Error: Invalid 'max_topic_alias_broker' value in configuration.") # Invalid value
do_test_broker_failure(conf_file, ["websockets_headers_size 65536"], 3, "Error: Websockets headers size must be between 0 and 65535 inclusive.") # Invalid 'value
do_test_broker_failure(conf_file, ["websockets_headers_size -1"], 3, "Error: Websockets headers size must be between 0 and 65535 inclusive.") # Invalid value
do_test_broker_failure(conf_file, ["memory_limit -1"], 3, "Error: Invalid 'memory_limit' value (-1).") # Invalid value

do_test_broker_failure(conf_file, ["sys_interval -1"], 3, "Error: Invalid 'sys_interval' value (-1).") # Invalid value
do_test_broker_failure(conf_file, ["sys_interval 65536"], 3, "Error: Invalid 'sys_interval' value (65536).") # Invalid value



exit(0)
