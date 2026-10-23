#!/usr/bin/env python3

# Check role publish quotas, their persistence, and MQTT acknowledgement codes.

from mosq_test_helper import *
from dynsec_helper import command_check
import json
import shutil

mosq_test.require_features(["WITH_CONTROL", "WITH_PLUGINS", "WITH_PLUGIN_DYNAMIC_SECURITY", "WITH_TLS"])

port = mosq_test.get_port()
conf_file = os.path.basename(__file__).replace('.py', '.conf')
config_file = Path(str(port), "dynamic-security.json")
with open(conf_file, 'w') as f:
    f.write(f"listener {port}\nallow_anonymous true\n")
    f.write(f"plugin {mosq_paths.plugin_dynamic_security}\n")
    f.write(f"plugin_opt_config_file {config_file}\n")

os.mkdir(str(port))
shutil.copyfile(source_dir / "dynamic-security-init.json", config_file)
sockets = []


def connect(clientid, username="admin", proto_ver=4):
    password = "admin" if username == "admin" else "password"
    if username is None:
        password = None
    sock = mosq_test.do_client_connect(
        mqtt_packets.gen_connect(clientid, username=username, password=password, proto_ver=proto_ver),
        mqtt_packets.gen_connack(rc=0, proto_ver=proto_ver), port=port, timeout=5)
    sockets.append(sock)
    return sock


def subscribe(sock, topic):
    mosq_test.do_send_receive(sock, mqtt_packets.gen_subscribe(1, topic, 0),
                             mqtt_packets.gen_suback(1, 0), "suback")


def command(name, error=None, **fields):
    response = {"command": name}
    if error:
        response["error"] = error
    command_check(admin, {"commands": [{"command": name, **fields}]}, {"responses": [response]})


def get_role(name):
    admin.sendall(mqtt_packets.gen_publish("$CONTROL/dynamic-security/v1", 0,
                  json.dumps({"commands": [{"command": "getRole", "rolename": name}]})))
    return json.loads(mosq_test.read_publish(admin))["responses"][0]["data"]["role"]


def publish(sock, payload="ok", qos=1, allowed=True, proto_ver=5):
    sock.sendall(mqtt_packets.gen_publish("limits/test", qos, payload, mid=2, proto_ver=proto_ver))
    if qos:
        ack = mqtt_packets.gen_puback if qos == 1 else mqtt_packets.gen_pubrec
        reason = -1 if allowed else 0x97
        mosq_test.expect_packet(sock, "publish ack", ack(2, proto_ver=proto_ver, reason_code=reason))
        if qos == 2 and allowed:
            mosq_test.do_send_receive(sock, mqtt_packets.gen_pubrel(2, proto_ver=proto_ver),
                                     mqtt_packets.gen_pubcomp(2, proto_ver=proto_ver), "pubcomp")
    else:
        # Fence the publish so an unexpectedly forwarded message is queued
        # before checking the observer's next packet.
        mosq_test.do_send_receive(sock, mqtt_packets.gen_pingreq(), mqtt_packets.gen_pingresp(), "ping")
    if allowed:
        mosq_test.expect_packet(observer, "forwarded publish", mqtt_packets.gen_publish("limits/test", 0, payload))
    else:
        mosq_test.do_send_receive(observer, mqtt_packets.gen_pingreq(), mqtt_packets.gen_pingresp(), "no forwarded publish")


rc = 1
broker = mosq_test.start_broker(filename=os.path.basename(__file__), use_conf=True, port=port)
try:
    admin = connect("admin-control")
    subscribe(admin, "$CONTROL/dynamic-security/#")
    observer = connect("observer")
    subscribe(observer, "limits/#")
    acl = [{"acltype": "publishClientSend", "topic": "limits/#", "allow": True}]
    rate = {"messages": 1, "perSeconds": 1000000, "burst": 2}
    # Control commands bypass MESSAGE_IN quotas, including under a limited role.
    command("createRole", rolename="control-limit", maxPublishSize=1, publishRateLimit=rate)
    command("addClientRole", username="admin", rolename="control-limit")
    command("createRole", rolename="limited", acls=acl, maxPublishSize=4, publishRateLimit=rate)
    command("createRole", rolename="unlimited", acls=acl)
    command("createGroup", groupname="devices", roles=[{"rolename": "limited"}])
    for name in ("alice", "bob"):
        command("createClient", username=name, password="password", roles=[{"rolename": "limited"}],
                groups=[{"groupname": "devices"}])
    command("createClient", username="carol", password="password", roles=[{"rolename": "unlimited"}])

    # Malformed policies must neither create a role nor partially modify one.
    invalid = [
        {"maxPublishSize": -1}, {"maxPublishSize": 1.5}, {"maxPublishSize": True},
        {"maxPublishSize": "4"}, {"maxPublishSize": 268435456}, {"maxPublishSize": None},
        {"publishRateLimit": []}, {"publishRateLimit": {}},
        {"publishRateLimit": {**rate, "messages": 0}},
        {"publishRateLimit": {**rate, "perSeconds": -1}},
        {"publishRateLimit": {**rate, "burst": 1.5}},
        {"publishRateLimit": {**rate, "burst": 2147483648}},
    ]
    for limits in invalid:
        command("createRole", error="Invalid publish limits", rolename="invalid", **limits)
        command("modifyRole", error="Invalid publish limits", rolename="limited", textname="changed", **limits)
    role = get_role("limited")
    assert "textname" not in role
    assert role["maxPublishSize"] == 4 and role["publishRateLimit"] == rate

    alice = connect("alice", "alice", 5)
    bob = connect("bob", "bob", 5)
    carol = connect("carol", "carol", 5)
    publish(alice, payload="large", allowed=False)
    publish(alice, payload="1234")
    publish(alice, qos=2)
    publish(alice, allowed=False)
    publish(alice, qos=2, allowed=False)
    publish(alice, qos=0, allowed=False)
    # Direct and inherited copies of the same role charge only once. Other
    # accounts with that role still have their own complete burst allowance.
    publish(bob)
    publish(bob)
    publish(bob, allowed=False)
    for _ in range(4):
        publish(carol, payload="unlimited payload")

    # A second connection or reconnect under the same username cannot reset it.
    alice2 = connect("alice-other-connection", "alice", 5)
    publish(alice2, allowed=False)
    alice.sendall(mqtt_packets.gen_disconnect())
    alice.close()
    alice = connect("alice", "alice", 5)
    publish(alice, allowed=False)

    # Editing unrelated metadata must not replenish an exhausted bucket.
    command("modifyRole", rolename="limited", textname="Devices")
    publish(alice, allowed=False)
    command("modifyRole", rolename="limited", publishRateLimit=None)
    publish(alice, payload="large", allowed=False)
    publish(alice)

    # Every role's limit applies, even if a higher-priority role allows the ACL.
    command("createRole", rolename="small", maxPublishSize=1)
    command("createClient", username="multi", password="password", roles=[
        {"rolename": "limited", "priority": 10}, {"rolename": "small", "priority": 0}])
    multi = connect("multi", "multi", 5)
    publish(multi, allowed=False)
    publish(multi, payload="x")

    # Group-only assignments and anonymous clients are subject to quotas too.
    command("modifyRole", rolename="limited", publishRateLimit=rate)
    # Rejection by a later role must not spend tokens in an earlier role.
    publish(multi, allowed=False)
    publish(multi, payload="x")
    publish(multi, payload="x")
    publish(multi, payload="x", allowed=False)
    command("createClient", username="group-only", password="password", groups=[{"groupname": "devices"}])
    grouped = connect("grouped", "group-only", 5)
    publish(grouped)
    publish(grouped)
    publish(grouped, allowed=False)
    command("setAnonymousGroup", groupname="devices")
    anon = connect("anonymous", None, 5)
    anon2 = connect("anonymous2", None, 5)
    publish(anon)
    publish(anon)
    publish(anon, allowed=False)
    publish(anon2)

    # Refill is independent of traffic and capped at the configured burst.
    command("modifyRole", rolename="limited", publishRateLimit={"messages": 1, "perSeconds": 1, "burst": 1})
    publish(alice)
    time.sleep(1.1)
    publish(alice)

    # MQTT 3 clients get the usual acknowledgement but no rejected delivery.
    command("modifyRole", rolename="limited", publishRateLimit=None)
    legacy = connect("legacy", "alice", 4)
    publish(legacy, payload="oversize", allowed=False, proto_ver=4)
    command("modifyRole", rolename="limited", maxPublishSize=0)
    publish(legacy, payload="now allowed", proto_ver=4)

    # Saved policies must survive a broker restart; runtime tokens need not.
    command("modifyRole", rolename="limited", maxPublishSize=4, publishRateLimit=rate)
    mosq_test.terminate_broker(broker)
    if mosq_test.wait_for_subprocess(broker):
        raise ValueError("broker did not stop cleanly")
    log = mosq_test.broker_log(broker)
    assert "publish limit exceeded | role=limited | client=bob | reason=rate | rejected=1" in log
    assert log.count("publish limit exceeded | role=limited | client=bob |") == 1
    assert "publish limit exceeded | role=small | client=multi | reason=size | rejected=1" in log
    broker = mosq_test.start_broker(filename=os.path.basename(__file__), use_conf=True, port=port)
    admin = connect("admin-restarted")
    subscribe(admin, "$CONTROL/dynamic-security/#")
    observer = connect("observer-restarted")
    subscribe(observer, "limits/#")
    role = get_role("limited")
    assert role["maxPublishSize"] == 4 and role["publishRateLimit"] == rate
    alice = connect("alice-restarted", "alice", 5)
    publish(alice, payload="large", allowed=False)
    publish(alice)
    publish(alice)
    publish(alice, allowed=False)
    # Deleting roles and clients must release their runtime quota state.
    command("deleteClient", username="alice")
    command("deleteRole", rolename="limited")

    # Invalid on-disk limits must fail startup rather than silently run with
    # an incomplete or unrestricted policy.
    mosq_test.terminate_broker(broker)
    if mosq_test.wait_for_subprocess(broker):
        raise ValueError("broker did not stop cleanly")
    config = json.loads(config_file.read_text())
    config["roles"][0]["maxPublishSize"] = -1
    config_file.write_text(json.dumps(config))
    failed_broker = mosq_test.start_broker(filename=os.path.basename(__file__), use_conf=True,
                                          port=port, expect_fail=True)
    assert failed_broker.returncode != 0
    assert "Error loading publish limits" in mosq_test.broker_log(failed_broker)
    rc = 0
finally:
    for sock in sockets:
        sock.close()
    mosq_test.terminate_broker(broker)
    if mosq_test.wait_for_subprocess(broker):
        rc = 1
    if rc:
        print(mosq_test.broker_log(broker))
    os.remove(conf_file)
    config_file.unlink(missing_ok=True)
    os.rmdir(str(port))

exit(rc)
