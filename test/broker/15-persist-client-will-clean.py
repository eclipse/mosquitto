#!/usr/bin/env python3

# Connect a client, add a subscription, disconnect, send a message with a
# different client, restore, reconnect, check it is received.

from mosq_test_helper import *
from persist_client_will_core import do_test

send_will_disconnect_rc = mqtt5_rc.DISCONNECT_WITH_WILL_MSG
normal_disconnect_rc = mqtt5_rc.NORMAL_DISCONNECTION

# Run test with different parameters:
# If disconnect_rc is not set the client will not disconnect
# session_expiry, will qos, will retain, disconnect_rc

send_will_disconnect_rc = mqtt5_rc.DISCONNECT_WITH_WILL_MSG

# non persistent client connected during crash
do_test(0, 0, 0)
do_test(0, 1, 0)
do_test(0, 0, 1)
do_test(0, 1, 1)

# non persistent client connected during crash, will delay does not matter
do_test(0, 0, 0, will_delay=30)
do_test(0, 1, 0, will_delay=30)
do_test(0, 0, 1, will_delay=30)
do_test(0, 1, 1, will_delay=30)

# non persistent client disconnecting with will sent before crash
do_test(0, 0, 0, disconnect_rc=send_will_disconnect_rc)
do_test(0, 1, 0, disconnect_rc=send_will_disconnect_rc)
do_test(0, 0, 1, disconnect_rc=send_will_disconnect_rc)
do_test(0, 1, 1, disconnect_rc=send_will_disconnect_rc)

# non persistent client disconnecting without will sent before crash
do_test(0, 0, 0, disconnect_rc=normal_disconnect_rc)
do_test(0, 1, 0, disconnect_rc=normal_disconnect_rc)
do_test(0, 0, 1, disconnect_rc=normal_disconnect_rc)
do_test(0, 1, 1, disconnect_rc=normal_disconnect_rc)

# Remove will msg by session takeover through reconnect
do_test(0, 1, 1, disconnect_rc=mqtt5_rc.SESSION_TAKEN_OVER)
# do_test(60, 1, 1, disconnect_rc=mqtt5_rc.SESSION_TAKEN_OVER)
