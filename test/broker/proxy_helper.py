import socket

PROXY_VER = 0x20
PROXY_CMD_LOCAL = 0x00
PROXY_CMD_PROXY = 0x01
PROXY_FAM_UNSPEC = 0x00
PROXY_FAM_IPV4 = 0x10
PROXY_FAM_IPV6 = 0x20
PROXY_FAM_UNIX = 0x30
PROXY_PROTO_UNSPEC = 0x00
PROXY_PROTO_TCP = 0x01
PROXY_PROTO_UDP = 0x02

def do_connect(port, data):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    sock.connect(("localhost", port))
    sock.send(data)
    return sock

def do_proxy_v2_connect(port, ver, cmd, fam, data):
    proxy_header = b"\x0d\x0a\x0d\x0a\x00\x0d\x0a\x51\x55\x49\x54\x0a"
    l = len(data)
    proxy_header += bytes([ver | cmd, fam, (l&0xFF00)>>8, l&0xFF])
    proxy_header += data
    return do_connect(port, proxy_header)

def do_proxy_v1_connect(port, data):
    return do_connect(port, data)
