#sudo cp libmosquitto.so.1 /tmp/

ulimit -SHn 524288
echo "5000 60999" > /proc/sys/net/ipv4/ip_local_port_range
echo 1 >  /proc/sys/net/ipv4/tcp_tw_reuse
echo 1 >  /proc/sys/net/ipv4/tcp_tw_recycle
export LD_LIBRARY_PATH=.
#ldconfig >/dev/null 2>&1
