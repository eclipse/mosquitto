#!/usr/bin/env python3

# Test parsing of command line args and errors. Does not test arg functionality.

from mosq_test_helper import *
import platform

mosq_test.require_features(["WITH_TLS"])

def do_test(args, rc_expected, response=None):
    proc = subprocess.run([mosq_paths.mosquitto_ctrl]
                    + args,
                    env=env, capture_output=True, encoding='utf-8', timeout=2)

    if response is not None:
        if response not in proc.stderr:
            print(len(proc.stderr))
            print(len(response))
            raise ValueError(f"'{response}' not in '{proc.stderr}'")

    if proc.returncode != rc_expected:
        raise ValueError(f"return code {proc.returncode} != expected {rc_expected} while testing args: {args}")

env = mosq_test.env_add_ld_library_path()

do_test(["-A"], 1, response="Error: -A argument given but no address specified.")
do_test(["--cafile"], 1, response="Error: --cafile argument given but no file specified.")
do_test(["--cafile", "missing", "broker", "listListeners"], 1, "Error: Problem setting TLS options: File not found.")
do_test(["--capath"], 1, response="Error: --capath argument given but no directory specified.")
do_test(["--cert"], 1, response="Error: --cert argument given but no file specified.")
do_test(["--cert", ssl_dir / "client.crt"], 1, response="Error: Both certfile and keyfile must be provided if one of them is set.")
do_test(["--help"], 1) # Gives generic help
do_test(["--key"], 1, response="Error: --key argument given but no file specified.")
do_test(["--key", ssl_dir / "client.key"], 1, response="Error: Both certfile and keyfile must be provided if one of them is set.")
do_test(["--ciphers"], 1, response="Error: --ciphers argument given but no ciphers specified.")
do_test(["-f"], 1, response="Error: -f argument given but no data file specified.")
do_test(["--host"], 1, response="Error: -h argument given but no host specified.")
do_test(["-i"], 1, response="Error: -i argument given but no id specified.")
do_test(["--keyform"], 1, response="Error: --keyform argument given but no keyform specified.")
do_test(["--keyform", "key"], 1, response="Error: If keyform is set, keyfile must be also specified.")
do_test(["--keyform", "key", "--cafile", "file", "--cert", "file", "--key", "file", "broker", "listListeners"], 1,
        response="Error: Problem setting key form, it must be one of 'pem' or 'engine'.")
do_test(['-L'], 1, response="Error: -L argument given but no URL specified.")
do_test(['-L', 'invalid://'], 1, response="Error: Unsupported URL scheme.")
do_test(['-L', 'mqtt://localhost'], 1, response="Error: Invalid URL for -L argument specified - topic missing.")
do_test(['-L', 'mqtts://localhost'], 1, response="Error: Invalid URL for -L argument specified - topic missing.")
do_test(['-L', 'mqtts://:@localhost/topic'], 1, response="Error: Empty username in URL.")
do_test(['-L', 'mqtts://localhost:/topic'], 1, response="Error: Empty port in URL.")
do_test(["-o"], 1, response="Error: -o argument given but no options file specified.")
do_test(["-p"], 1, response="Error: -p argument given but no port specified.")
do_test(["-p", "-1"], 1, response="Error: Invalid port given: -1")
do_test(["-p", "65536"], 1, response="Error: Invalid port given: 65536")
do_test(["-P"], 1, response="Error: -P argument given but no password specified.")

if mosq_test.check_features(["WITH_SOCKS"]):
    do_test(["--proxy"], 1, response="Error: --proxy argument given but no proxy url specified.")
    do_test(["--proxy", "mqtt://localhost"], 1, response="Error: Unsupported proxy protocol: mqtt://localhost")
    do_test(["--proxy", "socks5h://"], 1, response="Error: Invalid proxy.")
    do_test(["--proxy", "socks5h://localhost:0"], 1, response="Error: Invalid proxy port 0")
    do_test(["--proxy", "socks5h://localhost:65536"], 1, response="Error: Invalid proxy port 65536")
    do_test(["--proxy", "socks5h://username%@localhost"], 1, response="Error: Invalid URL encoding in username.")
    do_test(["--proxy", "socks5h://username%41@localhost"], 1, response="Error: Invalid URL encoding in username.")
    do_test(["--proxy", "socks5h://username:password%@localhost"], 1, response="Error: Invalid URL encoding in password.")
    do_test(["--proxy", "socks5h://username:password%41@localhost"], 1, response="Error: Invalid URL encoding in password.")
else:
    do_test(["--proxy", "socks5h://username:password%41@localhost"], 1, response="Error: Unknown option '--proxy'.")

if mosq_test.check_features(["WITH_TLS_PSK"]):
    do_test(["--psk"], 1, response="Error: --psk argument given but no key specified.")
    do_test(["--psk", "missing.psk"], 1, response="Error: --psk-identity required if --psk used.")
    do_test(["--psk-identity"], 1, response="Error: --psk-identity argument given but no identity specified.")
    do_test(["--cafile", ssl_dir / "all-ca.crt", "--psk", "missing.psk", "--psk-identity", "identity"], 1, response="Error: Only one of --psk or --cafile/--capath may be used at once.")

do_test(["-q"], 1, response="Error: -q argument given but no QoS specified.")
do_test(["-q", "-1"], 1, response="Error: Invalid QoS given: -1")
do_test(["-q", "3"], 1, response="Error: Invalid QoS given: 3")
do_test(["--tls-alpn"], 1, response="Error: --tls-alpn argument given but no protocol specified.")
do_test(["--tls-engine"], 1, response="Error: --tls-engine argument given but no engine_id specified.")
do_test(["--tls-engine-kpass-sha1"], 1, response="Error: --tls-engine-kpass-sha1 argument given but no kpass sha1 specified.")
do_test(["--tls-version"], 1, response="Error: --tls-version argument given but no version specified.")
do_test(["--username"], 1, response="Error: -u argument given but no username specified.")
do_test(["--unix"], 1, response="Error: --unix argument given but no socket path specified.")
do_test(["-V"], 1, response="Error: --protocol-version argument given but no version specified.")
do_test(["-V", "2"], 1, response="Error: Invalid protocol version argument given.")
do_test(["-V", "6"], 1, response="Error: Invalid protocol version argument given.")
do_test(["--unknown"], 1, response="Error: Unknown option '--unknown'.")
do_test(["--version"], 1) # Gives generic help

# Behaviour with incomplete args is now to run the shell, so these tests don't work
#do_test([], 1)
#do_test(["broker"], 1)
#do_test(["-A", "127.0.0.1"], 1) # Gives generic help
#do_test(["--cafile", ssl_dir / "all-ca.crt"], 1) # Gives generic help
#do_test(["--capath", ssl_dir], 1) # Gives generic help
#do_test(["--ciphers", "DEFAULT"], 1) # Gives generic help
#do_test(["--debug"], 1) # Gives generic help
#do_test(["-f", ssl_dir / "test"], 1) # Gives generic help
#do_test(["--host", "127.0.0.1"], 1) # Gives generic help
#do_test(["-i", "clientid"], 1) # Gives generic help
#do_test(["--insecure"], 1) # Gives generic help
#do_test(['-L', 'mqtts://localhost/'], 1)
#do_test(['-L', 'mqtts://username:password@localhost:1887/topic'], 1)
#do_test(["-o", "file"], 1) # Gives generic help
#do_test(["-p", "1887"], 1) # Gives generic help
#do_test(["-P", "password"], 1) # Gives generic help
#do_test(["--proxy", "socks5h://localhost"], 1) # Gives generic help
#do_test(["--proxy", "socks5h://username@localhost@localhost"], 1) # Gives generic help
#do_test(["--proxy", "socks5h://username@localhost:localhost:1080"], 1) # Gives generic help
#do_test(["--proxy", "socks5h://localhost:1080"], 1) # Gives generic help
#do_test(["--proxy", "socks5h://username@localhost"], 1) # Gives generic help
#do_test(["--proxy", "socks5h://username:password@localhost"], 1) # Gives generic help
#do_test(["--proxy", "socks5h://username:password@localhost:1080"], 1) # Gives generic help
#do_test(["--proxy", "socks5h://:"], 1) # Gives generic help
#do_test(["--proxy", "socks5h://@"], 1) # Gives generic help
#do_test(["--proxy", "socks5h://username%25@localhost"], 1) # Gives generic help
#do_test(["--proxy", "socks5h://%25username@localhost"], 1) # Gives generic help
#do_test(["--proxy", "socks5h://user%3aname@localhost"], 1) # Gives generic help
#do_test(["--proxy", "socks5h://user%40name@localhost"], 1) # Gives generic help
#do_test(["--proxy", "socks5h://username:password%25@localhost"], 1) # Gives generic help
#do_test(["--proxy", "socks5h://username:%25password@localhost"], 1) # Gives generic help
#do_test(["--proxy", "socks5h://username:password%3a@localhost"], 1) # Gives generic help
#do_test(["--proxy", "socks5h://username:password%40@localhost"], 1) # Gives generic help
#do_test(["-q", "1"], 1) # Gives generic help
#do_test(["--quiet"], 1) # Gives generic help
#do_test(["--tls-alpn", "protocol"], 1) # Gives generic help
#do_test(["--tls-engine", "engine"], 1) # Gives generic help
#do_test(["--tls-engine-kpass-sha1", "sha1"], 1) # Gives generic help
#do_test(["--tls-version", "tlsv1.3"], 1) # Gives generic help
#do_test(["--unix", "sock"], 1) # Gives generic help
#do_test(["--username", "username"], 1) # Gives generic help
#do_test(["-V", "31"], 1) # Gives generic help
#do_test(["-V", "311"], 1) # Gives generic help
#do_test(["-V", "5"], 1) # Gives generic help
#do_test(["--verbose"], 1) # Gives generic help

# Broker
do_test(["broker", "unknown"], 13, response="Command 'unknown' not recognised.")

if mosq_test.check_features(["WITH_PLUGINS", "WITH_PLUGIN_DYNAMIC_SECURITY"]):
    # Dynsec
    do_test(["dynsec", "unknown"], 13, response="Command 'unknown' not recognised.")
    do_test(["-f", "file", "dynsec", "setClientPassword", "admin", "admin", "-i"], 3, response="Error: -i argument given, but no iterations provided.\nError: Invalid input.")
    do_test(["-f", "file", "dynsec", "setClientPassword", "admin", "admin", "-c"], 3, response="Error: Unknown argument: -c\nError: Invalid input.")
    do_test(["dynsec", "createClient", "client", "-i"], 3, response="Error: -i argument given, but no clientid provided.\nError: Invalid input.")
    do_test(["dynsec", "createClient", "client", "-p"], 3, response="Error: -p argument given, but no password provided.\nError: Invalid input.")

# Env modification

if platform.system() == 'Windows':
    # Missing file
    env["USERPROFILE"] = "/tmp"
    do_test(["--cert", ssl_dir / "client.crt"], 1, response="Error: Both certfile and keyfile must be provided if one of them is set.")

    # Invalid file
    env["USERPROFILE"] = "."
    with open("mosquitto_ctrl.conf", "wt") as f:
        f.write(f"--cert {ssl_dir / 'client.crt'}\n")
        f.write(f"--key\n")
    do_test(["broker"], 1, response="Error: --key argument given but no file specified.")

    # Empty file
    env["USERPROFILE"] = "."
    with open("mosquitto_ctrl.conf", "w") as f:
        pass
    do_test(["--cert", ssl_dir / "client.crt"], 1, response="Error: Both certfile and keyfile must be provided if one of them is set.")
    os.remove("mosquitto_ctrl.conf")
else:
    # Missing file
    env["HOME"] = "/tmp"
    do_test(["--cert", ssl_dir / "client.crt"], 1, response="Error: Both certfile and keyfile must be provided if one of them is set.")

    # Invalid file
    env["XDG_CONFIG_HOME"] = "."
    with open("mosquitto_ctrl", "w") as f:
        f.write(f"--cert {ssl_dir / 'client.crt'}\n")
        f.write(f"--key\n")
    do_test(["broker"], 1, response="Error: --key argument given but no file specified.")

    # Empty file
    env["XDG_CONFIG_HOME"] = "."
    with open("mosquitto_ctrl", "w") as f:
        pass
    do_test(["--cert", ssl_dir / "client.crt"], 1, response="Error: Both certfile and keyfile must be provided if one of them is set.")
    os.remove("mosquitto_ctrl")

exit(0)
