from pathlib import Path
import mosq_test
import platform

if platform.system() == 'Windows':
    libend = "dll"
else:
    libend = "so"

def test_plugin(name):
    return Path(
        mosq_test.get_build_root(),
        "test",
        "broker",
        "c",
        mosq_test.get_build_type(),
        f"{name}.{libend}",
    )

mosquitto = Path(mosq_test.get_build_root(), 'src', mosq_test.get_build_type(), 'mosquitto')

mosquitto_db_dump = Path(mosq_test.get_build_root(), "apps", "db_dump", mosq_test.get_build_type(), "mosquitto_db_dump")
mosquitto_ctrl = Path(mosq_test.get_build_root(), "apps", "mosquitto_ctrl", mosq_test.get_build_type(), "mosquitto_ctrl")
mosquitto_passwd = Path(mosq_test.get_build_root(), "apps", "mosquitto_passwd", mosq_test.get_build_type(), "mosquitto_passwd")
mosquitto_signal = Path(mosq_test.get_build_root(), "apps", "mosquitto_signal", mosq_test.get_build_type(), "mosquitto_signal")

mosquitto_pub = Path(mosq_test.get_build_root(), "client", mosq_test.get_build_type(), "mosquitto_pub")
mosquitto_rr = Path(mosq_test.get_build_root(), "client", mosq_test.get_build_type(), "mosquitto_rr")
mosquitto_sub = Path(mosq_test.get_build_root(), "client", mosq_test.get_build_type(), "mosquitto_sub")

plugin_acl_file = Path(mosq_test.get_build_root(), "plugins", "acl-file", mosq_test.get_build_type(), f"mosquitto_acl_file.{libend}")
plugin_dynamic_security = Path(mosq_test.get_build_root(), "plugins", "dynamic-security", mosq_test.get_build_type(), f"mosquitto_dynamic_security.{libend}")
plugin_password_file = Path(mosq_test.get_build_root(), "plugins", "password-file", mosq_test.get_build_type(), f"mosquitto_password_file.{libend}")
plugin_persist_sqlite = Path(mosq_test.get_build_root(), "plugins", "persist-sqlite", mosq_test.get_build_type(), f"mosquitto_persist_sqlite.{libend}")
plugin_sparkplug_aware = Path(mosq_test.get_build_root(), "plugins", "sparkplug-aware", mosq_test.get_build_type(), f"mosquitto_sparkplug_aware.{libend}")
