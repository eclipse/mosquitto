#!/usr/bin/env python3

# Test many different config options at once, and also reloading. This is
# primarily intended as a test of the config code, not the functionality of the
# options being set.

from mosq_test_helper import *
import signal

def write_acl(filename):
    with open(filename, 'w') as f:
        f.write('user new_username\n')
        f.write('topic readwrite topic/one\n')

def write_config(filename, ports, per_listener_settings, plugver, acl_file):
    with open(filename, 'w') as f:
        f.write("per_listener_settings %s\n" % (per_listener_settings))

        # Global options
        f.write("allow_duplicate_messages true\n")
        f.write("autosave_interval 1\n")
        f.write("autosave_on_changes true\n")
        f.write("check_retain_source true\n")
        f.write("enable_control_api true\n")
        f.write("global_max_clients 10\n")
        f.write("global_max_connections 10\n")
        #f.write("include_dir path\n")
        f.write("global_max_connections 10\n")
        f.write("log_dest stderr\n")
        f.write("log_timestamp true\n")
        f.write("log_timestamp_format %Y-%m-%dT%H:%M:%S\n")
        f.write("log_type all\n")
        f.write("max_inflight_bytes 10000\n")
        f.write("max_inflight_messages 100\n")
        f.write("max_keepalive 60\n")
        f.write("max_packet_size 1000\n")
        f.write("max_queued_bytes 10000\n")
        f.write("max_queued_messages 100\n")
        f.write("message_size_limit 1000\n")
        f.write("memory_limit 100000000\n")
        f.write("persistence true\n")
        f.write(f"persistence_file {ports[0]}.db\n")
        f.write("persistence_location .\n")
        f.write("persistent_client_expiration 1h\n")
        f.write(f"pid_file {ports[0]}.pid\n")
        f.write("queue_qos0_messages true\n")
        f.write("retain_available true\n")
        f.write("retry_interval not-used\n")
        f.write("set_tcp_nodelay true\n")
        f.write("sys_interval 60\n")
        f.write("upgrade_outgoing_qos true\n")
        f.write("websockets_log_level 255\n")
        f.write("websockets_headers_size 4096\n")

        # Listener and global
        if not per_listener_settings:
            f.write("allow_zero_length_clientid false\n")
            f.write("auto_id_prefix pre\n")
            f.write(f"acl_file {acl_file}\n")

        # Bridge options
        f.write("connection bridge\n")
        f.write(f"address 127.0.0.1:{ports[2]} 127.0.0.1:{ports[3]}\n")
        f.write("bridge_alpn alpn\n")
        f.write("bridge_attempt_unsubscribe false\n")
        f.write("bridge_bind_address 127.0.0.1\n")
        f.write(f"bridge_cafile {ssl_dir}/all-ca.crt\n")
        f.write("bridge_capath asasdf\n")
        f.write(f"bridge_certfile {ssl_dir}/client.crt\n")
        f.write(f"bridge_keyfile {ssl_dir}/client.key\n")
        f.write("bridge_ciphers ECDHE-ECDSA-AES256-GCM-SHA384\n")
        f.write("bridge_ciphers_tls1.3 TLS_AES_256_GCM_SHA384\n")
        #f.write("bridge_identity identity\n")
        f.write("bridge_insecure true\n")
        f.write("bridge_max_packet_size 10000\n")
        f.write("bridge_max_topic_alias 1000\n")
        f.write("bridge_outgoing_retain false\n")
        f.write("bridge_protocol_version mqttv50\n")
        #f.write("bridge_psk\n")
        f.write("bridge_receive_maximum 100\n")
        #f.write("bridge_reload_type immediate\n")
        f.write("bridge_reload_type lazy\n")
        f.write("bridge_require_ocsp false\n")
        f.write("bridge_session_expiry_interval 63\n")
        f.write("bridge_tcp_keepalive 100 100 100\n")
        f.write("bridge_tcp_user_timeout 60\n")
        f.write("bridge_tls_use_os_certs true\n")
        f.write("bridge_tls_version tlsv1.2\n")
        f.write("local_cleansession true\n")
        f.write("local_clientid blci\n")
        #f.write("local_username username\n")
        #f.write("local_password password\n")
        f.write("connection_messages true\n")
        f.write("idle_timeout 60\n")
        f.write("keepalive_interval 40\n")
        f.write("notification_topic notifications\n")
        f.write("notifications false\n")
        f.write("notifications_local_only true\n")
        f.write("remote_clientid brci\n")
        f.write("remote_username username\n")
        f.write("remote_password password\n")
        f.write("restart_timeout 60\n")
        f.write("round_robin false\n")
        f.write("start_type lazy\n")
        f.write("threshold 100\n")
        f.write("try_private false\n")
        f.write("topic bridge both 1\n")

        # Default listener

        # Listeners
        f.write("plugin_load auth c/auth_plugin_v%d.so\n" % (plugver))
        f.write("plugin_opt_test true\n")
        f.write("auth_plugin_deny_special_chars false\n")

        f.write("listener %d\n" % (ports[0]))
        f.write("plugin_use auth\n")

        f.write("listener %d\n" % (ports[1]))
        f.write("allow_anonymous false\n")
        #f.write("psk_hint hint\n")

        f.write("listener %d\n" % (ports[2]))
        f.write("plugin_use auth\n")
        f.write("accept_protocol_versions 3,4,5\n")
        f.write("bind_interface lo\n")
        f.write(f"cafile {ssl_dir}/all-ca.crt\n")
        f.write(f"certfile {ssl_dir}/server.crt\n")
        f.write(f"keyfile {ssl_dir}/server.key\n")
        #f.write("capath path\n")
        f.write("ciphers ECDHE-ECDSA-AES256-GCM-SHA384\n")
        f.write("ciphers_tls1.3 TLS_AES_256_GCM_SHA384\n")
        f.write("clientid_prefixes client\n")
        f.write(f"crlfile {ssl_dir}/crl.pem\n")
        #f.write("dhparamfile file\n")
        f.write("disable_client_cert_date_checks true\n")
        f.write("http_dir dir\n")
        f.write("max_connections 10\n")
        f.write("max_qos 1\n")
        f.write("mount_point mount/\n")
        f.write("protocol websockets\n")
        f.write("require_certificate true\n")
        f.write("socket_domain ipv4\n")
        f.write("tls_version tlsv1.2\n")
        f.write("max_topic_alias 15\n")
        f.write("max_topic_alias_broker 15\n")
        f.write("use_identity_as_username true\n")
        f.write("use_subject_as_username true\n")
        f.write("use_username_as_clientid true\n")
        f.write("websockets_origin localhost\n")
        if per_listener_settings:
            f.write("allow_zero_length_clientid false\n")
            f.write("auto_id_prefix pre\n")
            f.write(f"acl_file {acl_file}\n")

        f.write("port %d\n" % (ports[3]))

def client_check(username, password, rc, port):
    connect_packet = mosq_test.gen_connect(client_id="client-id", username=username, password=password)
    connack_packet = mosq_test.gen_connack(rc=rc)
    sock = mosq_test.do_client_connect(connect_packet, connack_packet, port=port)
    sock.close()

def do_test(per_listener_settings):
    proto_ver = 5
    ports = mosq_test.get_port(4)
    conf_file = os.path.basename(__file__).replace('.py', '.conf')
    acl_file = os.path.basename(__file__).replace('.py', '.acl')
    write_acl(acl_file)
    write_config(conf_file, ports, per_listener_settings, 2, acl_file)

    broker = mosq_test.start_broker(filename=os.path.basename(__file__), use_conf=True, port=ports[0])

    rc = 1
    try:
        client_check("test-username", "cnwTICONIURW", 0, ports[0]) # Should succeed
        client_check("test-username", "cnwTICONIURW", 5, ports[1]) # Should fail

        client_check("bad-actor", "nope", 5, ports[0]) # Should fail
        client_check("bad-actor", "nope", 5, ports[1]) # Should fail

        client_check(None, None, 5, ports[0]) # Should fail
        client_check(None, None, 5, ports[1]) # Should fail

        broker.send_signal(signal.SIGHUP)
        client_check("test-username", "cnwTICONIURW", 0, ports[0]) # Should succeed

        broker.send_signal(signal.SIGHUP)
        client_check("test-username", "cnwTICONIURW", 0, ports[0]) # Should succeed

        rc = 0
    except Exception as err:
        print(err)
    finally:
        broker.terminate()
        broker.wait()
        os.remove(conf_file)
        os.remove(acl_file)
        try:
            os.remove(f"{ports[0]}.db")
        except FileNotFoundError:
            pass
        if broker.returncode == 139:
            # Crash
            print("Broker crashed!")
            rc = 1
        if rc:
            print(f"per_listener_settings:{per_listener_settings}")
            (_, stde) = broker.communicate()
            print(stde.decode('utf-8'))
            exit(rc)

do_test("false")
do_test("true")
