import os
from pathlib import Path
import sqlite3
import mosq_test

dir_in = 0
dir_out = 1

ms_invalid = 0
ms_publish_qos0 = 1
ms_publish_qos1 = 2
ms_wait_for_puback = 3
ms_publish_qos2 = 4
ms_wait_for_pubrec = 5
ms_resend_pubrel = 6
ms_wait_for_pubrel = 7
ms_resend_pubcomp = 8
ms_wait_for_pubcomp = 9
ms_send_pubrec = 10
ms_queued = 11


def write_config(filename, port, additional_config_entries : dict = {}):
    with open(filename, "w") as f:
        f.write("listener %d\n" % (port))
        f.write("allow_anonymous true\n")
        f.write(
            f"plugin {mosq_test.get_build_root()}/plugins/persist-sqlite/mosquitto_persist_sqlite.so\n"
        )
        f.write("plugin_opt_db_file %d/mosquitto.sqlite3\n" % (port))
        for entry, value in additional_config_entries.items():            
            f.write(f"{entry} {value}\n")


# The create_db_of_version contains the database schema version introduced with Pro Mosquitto 2.8.
# The list of supported version includes artificial versions, which are used for databases created
# prior to the current version
# 0.9.0: DB from Mosquitto without version info table
# 1.0.0: DB created with latest version of plugin
def init(port, create_db_of_version: list[int] = None):
    try:
        os.mkdir(str(port))
    except FileExistsError:
        try:
            os.remove(f"{port}/mosquitto.sqlite3")
        except FileNotFoundError:
            pass
    if create_db_of_version is not None:
        con = sqlite3.connect(f"{port}/mosquitto.sqlite3")
        cursor = con.cursor()
        for statement in [
            "PRAGMA page_size=4096;",
            "PRAGMA journal_mode=WAL;",
            "PRAGMA foreign_keys = ON;",
            "PRAGMA synchronous=1;",
            "CREATE TABLE base_msgs (store_id INT64 PRIMARY KEY,expiry_time INT64,topic STRING NOT NULL,payload BLOB,source_id STRING,source_username STRING,payloadlen INTEGER,source_mid INTEGER,source_port INTEGER,qos INTEGER,retain INTEGER,properties STRING);",
            "CREATE TABLE retains (topic STRING PRIMARY KEY,store_id INT64);",
            "CREATE TABLE clients (client_id TEXT PRIMARY KEY,username TEXT,connection_time INT64,will_delay_time INT64,session_expiry_time INT64,listener_port INT,max_packet_size INT,max_qos INT,retain_available INT,session_expiry_interval INT,will_delay_interval INT);",
            "CREATE TABLE subscriptions (client_id TEXT NOT NULL,topic TEXT NOT NULL,subscription_options INTEGER,subscription_identifier INTEGER,PRIMARY KEY (client_id, topic) );",
        ]:
            cursor.execute(statement)
        if create_db_of_version[0] == 0 and create_db_of_version[1] == 9:
            for statement in [
                "CREATE TABLE client_msgs (client_id TEXT NOT NULL,cmsg_id INT64,store_id INT64,dup INTEGER,direction INTEGER,mid INTEGER,qos INTEGER,retain INTEGER,state INTEGER,subscription_identifier INTEGER);",
            ]:
                cursor.execute(statement)
        elif create_db_of_version[0] >= 1:
            for statement in [
                "CREATE TABLE client_msgs (client_id TEXT NOT NULL,cmsg_id INT64,store_id INT64,dup INTEGER,direction INTEGER,mid INTEGER,qos INTEGER,retain INTEGER,state INTEGER,subscription_identifier INTEGER);",
                "CREATE TABLE version_info (component TEXT NOT NULL,major INTEGER NOT NULL,minor INTEGER NOT NULL,patch INTEGER NOT NULL);",
                f"INSERT INTO version_info(component,major,minor,patch) VALUES ('database_schema',{','.join([str(i) for i in create_db_of_version])});",
            ]:
                cursor.execute(statement)

        cursor.close()
        con.commit()
        con.close()
        # We need to set write permission to everybody as broker will start with privilege drop
        os.chmod(f"{port}/mosquitto.sqlite3", 0o666)

def cleanup(port):
    rc = 1
    try:
        os.remove(f"{port}/mosquitto.sqlite3")
    except FileNotFoundError:
        pass
    try:
        os.rmdir(f"{port}")
        rc = 0
    except OSError as e:
        if Path(str(port), "mosquitto.sqlite3-wal").stat().st_size == 0:
            # some versions of sqlite3 do not remove the wal file
            # thus we make sure that the file is at least empty (no pending db transactions)
            rc = 0
        else:
            print(f"ERROR sqlite3 file not removed after shutdown")
        try:
            os.remove(f"{port}/mosquitto.sqlite3-shm")
        except FileNotFoundError:
            pass
        try:
            os.remove(f"{port}/mosquitto.sqlite3-wal")
        except FileNotFoundError:
            pass
        os.rmdir(f"{port}")
    return rc


def check_version_infos(port, database_schema_version):
    con = sqlite3.connect(f"{port}/mosquitto.sqlite3")
    cur = con.cursor()
    cur.execute(
        "SELECT major,minor,patch FROM version_info WHERE component = 'database_schema';"
    )
    row = cur.fetchone()
    assert len(row) == len(database_schema_version)
    for i in range(len(row)):
        assert row[i] == database_schema_version[i]
    con.close()

def check_counts(
    port,
    clients=0,
    client_msgs_in=0,
    client_msgs_out=0,
    base_msgs=0,
    retain_msgs=0,
    subscriptions=0,
):
    con = sqlite3.connect(f"{port}/mosquitto.sqlite3")
    cur = con.cursor()
    cur.execute("SELECT COUNT(*) FROM clients")
    row = cur.fetchone()
    if row[0] != clients:
        raise ValueError("Found %d clients, expected %d" % (row[0], clients))

    cur.execute("SELECT COUNT(*) FROM client_msgs WHERE direction=0")
    row = cur.fetchone()
    if row[0] != client_msgs_in:
        raise ValueError(
            "Found %d client_msgs_in, expected %d" % (row[0], client_msgs_in)
        )

    cur.execute("SELECT COUNT(*) FROM client_msgs WHERE direction=1")
    row = cur.fetchone()
    if row[0] != client_msgs_out:
        raise ValueError(
            "Found %d client_msgs_out, expected %d" % (row[0], client_msgs_out)
        )

    cur.execute("SELECT COUNT(*) FROM subscriptions")
    row = cur.fetchone()
    if row[0] != subscriptions:
        raise ValueError(
            "Found %d subscriptions, expected %d" % (row[0], subscriptions)
        )

    cur.execute("SELECT COUNT(*) FROM base_msgs")
    row = cur.fetchone()
    if row[0] != base_msgs:
        raise ValueError("Found %d base_msgs, expected %d" % (row[0], base_msgs))

    cur.execute("SELECT COUNT(*) FROM retains")
    row = cur.fetchone()
    if row[0] != retain_msgs:
        raise ValueError("Found %d retain_msgs, expected %d" % (row[0], retain_msgs))
    con.close()


def check_client(
    port,
    client_id,
    username,
    will_delay_time,
    session_expiry_time,
    listener_port,
    max_packet_size,
    max_qos,
    retain_available,
    session_expiry_interval,
    will_delay_interval,
):
    # "Fix" the infinite session expiry interval as mangled by an int32 conversion.
    if session_expiry_interval == 4294967295:
        session_expiry_interval = -1

    con = sqlite3.connect(f"{port}/mosquitto.sqlite3")
    cur = con.cursor()
    cur.execute(
        "SELECT client_id, username, will_delay_time, session_expiry_time, "
        + "listener_port, max_packet_size, max_qos, retain_available, "
        + "session_expiry_interval, will_delay_interval "
        + "FROM clients"
    )
    row = cur.fetchone()

    if row[0] != client_id:
        raise ValueError("Invalid client_id %s / %s" % (row[0], client_id))

    if username is not None and row[1] != username:
        raise ValueError("Invalid username %s / %s" % (row[1], username))

    if (will_delay_time == 0 and row[2] != 0) or (will_delay_time != 0 and row[2] == 0):
        raise ValueError("Invalid will_delay_time %d / %d" % (row[2], will_delay_time))

    if (session_expiry_time == 0 and row[3] != 0) or (
        session_expiry_time != 0 and row[3] == 0
    ):
        raise ValueError(
            "Invalid session_expiry_time %d / %d" % (row[3], session_expiry_time)
        )

    if listener_port is not None and row[4] != listener_port:
        raise ValueError("Invalid listener_port %d / %d" % (row[4], listener_port))

    if row[5] != max_packet_size:
        raise ValueError("Invalid max_packet_size %d / %d" % (row[5], max_packet_size))

    if row[6] != max_qos:
        raise ValueError("Invalid max_qos %d / %d" % (row[6], max_qos))

    if row[7] != retain_available:
        raise ValueError(
            "Invalid retain_available %d / %d" % (row[7], retain_available)
        )

    if row[8] != session_expiry_interval:
        raise ValueError(
            "Invalid session_expiry_interval %d / %d"
            % (row[8], session_expiry_interval)
        )

    if row[9] != will_delay_interval:
        raise ValueError(
            "Invalid will_delay_interval %d / %d" % (row[9], will_delay_interval)
        )
    con.close()


def check_subscription(
    port, client_id, topic, subscription_options, subscription_identifier
):
    con = sqlite3.connect(f"{port}/mosquitto.sqlite3")
    cur = con.cursor()
    cur.execute(
        "SELECT client_id, topic, subscription_options, subscription_identifier "
        + "FROM subscriptions"
    )
    row = cur.fetchone()

    if row[0] != client_id:
        raise ValueError("Invalid client_id %s / %s" % (row[0], client_id))

    if row[1] != topic:
        raise ValueError("Invalid topic %s / %s" % (row[1], topic))

    if row[2] != subscription_options:
        raise ValueError(
            "Invalid subscription_options %d / %d" % (row[2], subscription_options)
        )

    if row[3] != subscription_identifier:
        raise ValueError(
            "Invalid subscription_identifier %d / %d"
            % (row[3], subscription_identifier)
        )
    con.close()


def check_client_msg(
        port, client_id, cmsg_id, store_id, dup, direction, mid, qos, retain, state, idx=0
):
    con = sqlite3.connect(f"{port}/mosquitto.sqlite3")
    try:
        cur = con.cursor()
        cur.execute(
            "SELECT client_id,cmsg_id,store_id,dup,direction,mid,qos,retain,state "
            + "FROM client_msgs "
            + "ORDER BY cmsg_id"
        )
        for i in range(0, idx + 1):
            row = cur.fetchone()

        if row[0] != client_id:
            raise ValueError("Invalid client_id %s / %s" % (row[0], client_id))

        if row[1] != cmsg_id:
            raise ValueError("Invalid cmsg_id %s / %s" % (row[1], cmsg_id))

        if row[2] != store_id:
            raise ValueError("Invalid store_id %d / %d" % (row[2], store_id))

        if row[3] != dup:
            raise ValueError("Invalid dup %d / %d" % (row[3], dup))

        if row[4] != direction:
            raise ValueError("Invalid direction %d / %d" % (row[4], direction))

        if row[5] != mid:
            raise ValueError("Invalid mid %d / %d" % (row[5], mid))

        if row[6] != qos:
            raise ValueError("Invalid qos %d / %d" % (row[6], qos))

        if row[7] != retain:
            raise ValueError("Invalid retain %d / %d" % (row[7], retain))

        if row[8] != state:
            raise ValueError("Invalid state %d / %d" % (row[8], state))
    except ValueError as err:
        raise ValueError(str(err)+ f" at index {idx}") from err
    finally:
        con.close()


def check_base_msg(
    port,
    expiry_time,
    topic,
    payload,
    source_id,
    source_username,
    payloadlen,
    source_mid,
    source_port,
    qos,
    retain,
    idx=0,
):
    con = sqlite3.connect(f"{port}/mosquitto.sqlite3")
    try:
        cur = con.cursor()
        cur.execute(
            "SELECT store_id,expiry_time,topic,payload,source_id,source_username, "
            + "payloadlen, source_mid, source_port, qos, retain "
            + "FROM base_msgs "
        )
        for i in range(0, idx + 1):
            row = cur.fetchone()
        
        if row[0] == 0:
            raise ValueError("Invalid store_id %d / %d" % (row[0], store_id))

        if (expiry_time == 0 and row[1] != 0) or (expiry_time != 0 and row[1] == 0):
            raise ValueError("Invalid expiry_time %d / %d" % (row[1], expiry_time))

        if row[2] != topic:
            raise ValueError("Invalid topic %s / %s" % (row[2], topic))

        if row[3] != payload:
            raise ValueError("Invalid payload %s / %s" % (row[3], payload))

        if row[4] != source_id:
            raise ValueError("Invalid source_id %s / %s" % (row[4], source_id))

        if row[5] != source_username:
            raise ValueError("Invalid source_username %s / %s" % (row[5], source_username))

        if row[6] != payloadlen or (payloadlen != 0 and row[6] != len(row[3])):
            raise ValueError("Invalid payloadlen %d / %d" % (row[6], payloadlen))

        if row[7] != source_mid:
            raise ValueError("Invalid source_mid %d / %d" % (row[7], source_mid))

        if row[8] != source_port:
            raise ValueError("Invalid source_port %d / %d" % (row[8], source_port))

        if row[9] != qos:
            raise ValueError("Invalid qos %d / %d" % (row[9], qos))

        if row[10] != retain:
            raise ValueError("Invalid retain %d / %d" % (row[10], retain))
    except ValueError as err:
        raise ValueError(str(err)+ f" at index {idx}") from err
    finally:
        con.close()

    return row[0]


def check_retain(port, topic, store_id):
    con = sqlite3.connect(f"{port}/mosquitto.sqlite3")
    cur = con.cursor()
    cur.execute("SELECT store_id FROM retains WHERE topic=?", (topic,))
    row = cur.fetchone()

    if row[0] != store_id:
        raise ValueError("Invalid store_id %d / %d" % (row[0], store_id))
    con.close()
