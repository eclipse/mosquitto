#!/usr/bin/env python3
"""
The auth bridge plugin mechanism will be tested in various situations.

With this a bridge plugin can provide credentials for broker
authentication.

For each of these tests a bridge configuration will be created and
a broker will be started with this configuration. The broker is then
in the role of a bridge and have identify itself with username/password.
On the other end of the connection a simulated broker receives a connection
request and analyses it's content and username/password.

For a list of tests see documentation in the main() function.
"""

from mosq_test_helper import *

# Normally we don't want tests to spew debug, but if you're working on a test, it's useful
VERBOSE_TEST = True

def tprint(*args, **kwargs):
    if VERBOSE_TEST:
        print(" ".join(map(str, args)), **kwargs)


def write_bridge_config(
    proto_ver,
    bridge_test_config,
    remote_port,
    listen_port,
    username=None,
    password=None,
    plugin_v1=None,
    plugin_v2=None,
):
    """
    This is the configuration for our "bridge" broker
    """
    if proto_ver == 4:
        bridge_protocol = "mqttv311"
    else:
        bridge_protocol = "mqttv50"

    filename = os.path.basename(__file__).replace(".py", ".conf")
    with open(filename, "w") as f:
        f.write("listener %d\n" % (listen_port))
        f.write("allow_anonymous false\n")
        f.write("\n")
        f.write(f"connection {bridge_test_config}\n")
        f.write("address 127.0.0.1:%d\n" % (remote_port))
        f.write("\n")
        f.write("topic br_out/# out 0\n")
        f.write("topic br_in/# in 0\n")
        if username and password:
            f.write(f"remote_username {username}\n")
            f.write(f"remote_password {password}\n")
        f.write("\n")
        f.write("keepalive_interval 60\n")
        f.write("bridge_protocol_version %s\n" % (bridge_protocol))
        if plugin_v1:
            f.write(f"plugin c/{plugin_v1}.so\n")
        if plugin_v2:
            f.write(f"plugin c/{plugin_v2}.so\n")


def do_test(test_params):
    """
    We starting the "bridge" broker and comparing the connect datagram
    against the specified one
    """
    proto_ver, bridge_listen_port, broker_listen_port, connect_packet = test_params

    rc = 1
    connack_packet = mosq_test.gen_connack(rc=0, proto_ver=proto_ver)

    ssock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ssock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ssock.settimeout(40)
    ssock.bind(("", broker_listen_port))
    ssock.listen(5)

    try:
        bridge = mosq_test.start_broker(
            filename=os.path.basename(__file__), port=bridge_listen_port, use_conf=True
        )

        (broker, address) = ssock.accept()
        broker.settimeout(10)

        mosq_test.expect_packet(broker, "connect", connect_packet)
        broker.send(connack_packet)
        broker.close()
        rc = 0

    except Exception as e:
        print(e)
    except mosq_test.TestError:
        pass
    finally:
        try:
            broker.close()
        except NameError:
            pass

        bridge.terminate()
        if mosq_test.wait_for_subprocess(bridge):
            print("bridge not terminated")
            if rc == 0:
                rc = 1
        (stdo, stde) = bridge.communicate()
        ssock.close()
        if rc:
            print(stde.decode("utf-8"))
            exit(rc)


def get_proto_ver_connect(proto_ver):
    if proto_ver == 4:
        return 128 + 4
    else:
        return 5


def get_connection_packet(proto_ver, user, passw, connection):
    proto_ver_connect = get_proto_ver_connect(proto_ver)
    client_id = socket.gethostname() + "." + connection
    properties = mqtt5_props.gen_uint16_prop(mqtt5_props.TOPIC_ALIAS_MAXIMUM, 10)
    properties += mqtt5_props.gen_uint16_prop(mqtt5_props.RECEIVE_MAXIMUM, 20)
    will_props = mqtt5_props.gen_byte_prop(mqtt5_props.PAYLOAD_FORMAT_INDICATOR, 0x30)
    will_tpc = f"$SYS/broker/connection/{client_id}/state"
    return mosq_test.gen_connect(
        client_id,
        clean_session=False,
        username=user,
        password=passw,
        will_retain=True,
        will_topic=will_tpc,
        will_qos=1,
        will_payload=b"0",
        proto_ver=proto_ver_connect,
        properties=properties,
    )


def test_no_auth_plugin(proto_ver):
    """
    We are testing a connect without any pluging.
    username/password is set in the configuration file
    """
    tprint(f"-- Test: {sys._getframe().f_code.co_name}, protocol version = {proto_ver}")

    (bridge_listen_port, broker_listen_port) = mosq_test.get_port(2)
    user = "Werner"
    passw = "Heisenberg"
    connection = "none_v1"

    write_bridge_config(
        proto_ver,
        connection,
        broker_listen_port,
        bridge_listen_port,
        username=user,
        password=passw,
    )

    connect_packet = get_connection_packet(proto_ver, user, passw, connection)
    do_test((proto_ver, bridge_listen_port, broker_listen_port, connect_packet))


def test_auth_plugin_default_1(proto_ver):
    """
    We are testing a connect with pluging auth_brige_v1.
    Configuration: bridge_name = default_v1
    Plugin yields: username = Albert
                   password = Einstein
    """
    tprint(f"-- Test: {sys._getframe().f_code.co_name}, protocol version = {proto_ver}")

    user = "Albert"
    passw = "Einstein"
    connection = "default_v1"

    (bridge_listen_port, broker_listen_port) = mosq_test.get_port(2)
    write_bridge_config(
        proto_ver,
        connection,
        broker_listen_port,
        bridge_listen_port,
        plugin_v1="bridge_auth_v1",
    )

    connect_packet = get_connection_packet(proto_ver, user, passw, connection)
    do_test((proto_ver, bridge_listen_port, broker_listen_port, connect_packet))


def test_auth_plugin_overwrite_1(proto_ver):
    """
    We are testing a connect with pluging auth_brige_v1.
    Configuration: bridge_name = default_v1
    Plugin yields: username = Albert
                   password = Einstein
    This will overwrite exitisting configured remote_username/remote_password
    """
    tprint(f"-- Test: {sys._getframe().f_code.co_name}, protocol version = {proto_ver}")

    user = "Enrico"
    passw = " Fermi"
    connection = "default_v1"

    (bridge_listen_port, broker_listen_port) = mosq_test.get_port(2)
    write_bridge_config(
        proto_ver,
        connection,
        broker_listen_port,
        bridge_listen_port,
        username=user,
        password=passw,
        plugin_v1="bridge_auth_v1",
    )

    connect_packet = get_connection_packet(proto_ver, "Albert", "Einstein", connection)
    do_test((proto_ver, bridge_listen_port, broker_listen_port, connect_packet))


def test_auth_plugin_defer_1(proto_ver):
    """
    Configuration: defer_v1
    Plugin yields: username = <unchanged>
                   password = <unchanged>
    Plugin yields MOSQ_ERR_PLUGIN_DEFER, hence configured
    remote_username/remote_password will be used instead
    """
    tprint(f"-- Test: {sys._getframe().f_code.co_name}, protocol version = {proto_ver}")

    user = "Paul"
    passw = "Dirac"
    connection = "defer_v1"

    (bridge_listen_port, broker_listen_port) = mosq_test.get_port(2)
    write_bridge_config(
        proto_ver,
        connection,
        broker_listen_port,
        bridge_listen_port,
        username=user,
        password=passw,
        plugin_v1="bridge_auth_v1",
    )

    connect_packet = get_connection_packet(proto_ver, user, passw, connection)
    do_test((proto_ver, bridge_listen_port, broker_listen_port, connect_packet))


def test_auth_plugin_denied_1(proto_ver):
    """
    Configuration: bridge_name = denied_v1
    Plugin yields: username = <unchanged>
                   password = <unchanged>
    Plugin yields a denied, hence no username/password will be set at all
    """
    tprint(f"-- Test: {sys._getframe().f_code.co_name}, protocol version = {proto_ver}")

    user = "Paul"
    passw = "Dirac"
    connection = "denied_v1"

    (bridge_listen_port, broker_listen_port) = mosq_test.get_port(2)
    write_bridge_config(
        proto_ver,
        connection,
        broker_listen_port,
        bridge_listen_port,
        username=user,
        password=passw,
        plugin_v1="bridge_auth_v1",
    )

    connect_packet = get_connection_packet(proto_ver, None, None, connection)
    do_test((proto_ver, bridge_listen_port, broker_listen_port, connect_packet))


def test_auth_plugin_not_found_1(proto_ver):
    """
    Configuration: bridge_name = not_found_v1
    Plugin yields: username = <unchanged>
                   password = <unchanged>
    Plugin yields no username/password, remote_username/remote_password
    will be used instead
    """
    tprint(f"-- Test: {sys._getframe().f_code.co_name}, protocol version = {proto_ver}")

    user = "Paul"
    passw = "Dirac"
    connection = "not_found_v1"

    (bridge_listen_port, broker_listen_port) = mosq_test.get_port(2)
    write_bridge_config(
        proto_ver,
        connection,
        broker_listen_port,
        bridge_listen_port,
        username=user,
        password=passw,
        plugin_v1="bridge_auth_v1",
    )

    connect_packet = get_connection_packet(proto_ver, user, passw, connection)
    do_test((proto_ver, bridge_listen_port, broker_listen_port, connect_packet))


def test_auth_plugin_default_2(proto_ver):
    """
    We are testing a connect with pluging auth_brige_v1, auth_bridge_v2.
    Configuration: default_v2
    Plugin yields: username = Marie
                   password = Curie
    """
    tprint(f"-- Test: {sys._getframe().f_code.co_name}, protocol version = {proto_ver}")

    user = "Marie"
    passw = "Curie"
    connection = "default_v2"

    (bridge_listen_port, broker_listen_port) = mosq_test.get_port(2)
    write_bridge_config(
        proto_ver,
        connection,
        broker_listen_port,
        bridge_listen_port,
        plugin_v1="bridge_auth_v1",
        plugin_v2="bridge_auth_v2",
    )
    connect_packet = get_connection_packet(proto_ver, user, passw, connection)
    do_test((proto_ver, bridge_listen_port, broker_listen_port, connect_packet))


def test_auth_plugin_overwrite_2(proto_ver):
    """
    We are testing a connect with pluging auth_brige_v1 and auth_bridge_v1.
    Configuration: default_v2
    Plugin auth_bridge_v2 yields: username = Marie
                                  password = Curie
    This will overwrite exitisting configured remote_username/remote_password
    """
    tprint(f"-- Test: {sys._getframe().f_code.co_name}, protocol version = {proto_ver}")

    user = "Enrico"
    passw = " Fermi"
    connection = "default_v2"

    (bridge_listen_port, broker_listen_port) = mosq_test.get_port(2)
    write_bridge_config(
        proto_ver,
        connection,
        broker_listen_port,
        bridge_listen_port,
        username=user,
        password=passw,
        plugin_v1="bridge_auth_v1",
        plugin_v2="bridge_auth_v2",
    )

    connect_packet = get_connection_packet(proto_ver, "Marie", "Curie", connection)
    do_test((proto_ver, bridge_listen_port, broker_listen_port, connect_packet))


def test_auth_plugin_defer_2(proto_ver):
    """
    Both plugins are returning MOSQ_ERR_PLUGIN_DEFER, hence configured
    remote_username/remote_password will be used instead
    Configuration: defer_v2
    Plugin yields: username = <unchanged>
                   password = <unchanged>
    """
    tprint(f"-- Test: {sys._getframe().f_code.co_name}, protocol version = {proto_ver}")

    user = "Paul"
    passw = "Dirac"
    connection = "defer_v2"

    (bridge_listen_port, broker_listen_port) = mosq_test.get_port(2)
    write_bridge_config(
        proto_ver,
        connection,
        broker_listen_port,
        bridge_listen_port,
        username=user,
        password=passw,
        plugin_v1="bridge_auth_v1",
        plugin_v2="bridge_auth_v2",
    )

    connect_packet = get_connection_packet(proto_ver, user, passw, connection)
    do_test((proto_ver, bridge_listen_port, broker_listen_port, connect_packet))


def test_auth_plugin_denied_2(proto_ver):
    """
    Configuration: denied_v2
    Plugin yields: username = <unchanged>
                   password = <unchanged>
    Plugin yields a denied, hence no username/password will be set at all
    """
    tprint(f"-- Test: {sys._getframe().f_code.co_name}, protocol version = {proto_ver}")

    user = "Paul"
    passw = "Dirac"
    connection = "denied_v2"

    (bridge_listen_port, broker_listen_port) = mosq_test.get_port(2)
    write_bridge_config(
        proto_ver,
        connection,
        broker_listen_port,
        bridge_listen_port,
        username=user,
        password=passw,
        plugin_v1="bridge_auth_v1",
        plugin_v2="bridge_auth_v2",
    )

    connect_packet = get_connection_packet(proto_ver, None, None, connection)
    do_test((proto_ver, bridge_listen_port, broker_listen_port, connect_packet))


def test_auth_plugin_not_found_2(proto_ver):
    """
    Configuration: not_found_v2
    Plugin yields: username = <unchanged>
                   password = <unchanged>
    Plugin yields no username/password, remote_username/remote_password
    will be used instead
    """
    tprint(f"-- Test: {sys._getframe().f_code.co_name}, protocol version = {proto_ver}")

    user = "Paul"
    passw = "Dirac"
    connection = "not_found_v2"

    (bridge_listen_port, broker_listen_port) = mosq_test.get_port(2)
    write_bridge_config(
        proto_ver,
        connection,
        broker_listen_port,
        bridge_listen_port,
        username=user,
        password=passw,
        plugin_v1="bridge_auth_v1",
        plugin_v2="bridge_auth_v2",
    )

    connect_packet = get_connection_packet(proto_ver, user, passw, connection)
    do_test((proto_ver, bridge_listen_port, broker_listen_port, connect_packet))


def test_auth_both_plugins_default_1(proto_ver):
    """
    We are testing a connect with pluging auth_brige_v1, auth_bridge_v2.
    Configuration: default_v1
    Plugin auth_bridge_v1 yields: username = Albert
                                  password = Einstein
    """
    tprint(f"-- Test: {sys._getframe().f_code.co_name}, protocol version = {proto_ver}")

    user = "Werner"
    passw = "Heisenberg"
    connection = "default_v1"

    (bridge_listen_port, broker_listen_port) = mosq_test.get_port(2)
    write_bridge_config(
        proto_ver,
        connection,
        broker_listen_port,
        bridge_listen_port,
        plugin_v1="bridge_auth_v1",
        plugin_v2="bridge_auth_v2",
    )
    connect_packet = get_connection_packet(proto_ver, "Albert", "Einstein", connection)
    do_test((proto_ver, bridge_listen_port, broker_listen_port, connect_packet))


def main():
    """Process all tests
    plugins used: auth_bridge_v1.so, auth_bridge_v2.so

    Test         |   auth_bridge_v1       |    auth_bridge_v2     | Result
    --------------------------------------------------------------------------------
    no_plugin     |          -            |           -           | remote_username/remote_password will be used
    default_v1    | MOSQ_ERR_SUCCESS      |           -           | NO remote_username/remote_password is set
                  |                       |                       |   plugin username/password will be used
    overwrite_v1  | MOSQ_ERR_SUCCESS      |           -           | remote_username/remote_password is set but
                  |                       |                       |   plugin username/password will be used
    defer_ v1     | MOSQ_ERR_PLUGIN_DEFER |           -           | remote_username/remote_password will be used
    denied_v1     | MOSQ_ERR_AUTH_DENIED  |           -           | NO username/password will be used at all
    not_found_v1  | MOSQ_ERR_NOT_FOUND    |           -           | remote_username/remote_password will be used
    --------------|-----------------------|-----------------------|-----------------------------------------------------------------
    default_v2    | MOSQ_ERR_PLUGIN_DEFER | MOSQ_ERR_SUCCESS      | NO remote_username/remote_password is set
                  |                       |                       |   plugin auth_bridge_v2 username/password will be used
    overwrite_v2  | MOSQ_ERR_PLUGIN_DEFER | MOSQ_ERR_SUCCESS      | remote_username/remote_password is set but
                  |                       |                       |   plugin auth_bridge_v2 username/password will be used
    defer_ v2     | MOSQ_ERR_PLUGIN_DEFER | MOSQ_ERR_PLUGIN_DEFER | remote_username/remote_password will be used
    denied_v2     | MOSQ_ERR_PLUGIN_DEFER | MOSQ_ERR_AUTH_DENIED  | NO username/password will be used at all
    not_found_v2  | MOSQ_ERR_PLUGIN_DEFER | MOSQ_ERR_NOT_FOUND    | remote_username/remote_password will be used
    --------------|-----------------------|-----------------------|-----------------------------------------------------------------
    default_v1    | MOSQ_ERR_SUCCESS      | MOSQ_ERR_NOT_FOUND    | auth_plugin_v1 remote_username/remote_password will be used
    """

    # Do all tests for version 4 and version 5
    for version in range(4, 6):
        test_no_auth_plugin(version)
        test_auth_plugin_default_1(version)
        test_auth_plugin_overwrite_1(version)
        test_auth_plugin_defer_1(version)
        test_auth_plugin_denied_1(version)
        test_auth_plugin_not_found_1(version)

        test_auth_plugin_default_2(version)
        test_auth_plugin_overwrite_2(version)
        test_auth_plugin_defer_2(version)
        test_auth_plugin_denied_2(version)
        test_auth_plugin_not_found_2(version)

        test_auth_both_plugins_default_1(version)

    config_filename = os.path.basename(__file__).replace(".py", ".conf")
    os.remove(config_filename)
    return 0


if __name__ == "__main__":
    sys.exit(main())  # next section explains the use of sys.exit
