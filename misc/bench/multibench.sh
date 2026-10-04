#!/bin/bash
# Aggregate throughput with M publishers and N subscribers on one topic.
#
# Usage: multibench.sh BROKER_BIN [M] [N] [PER] [SIZE]
#   BROKER_BIN  path to the mosquitto broker to test
#   M           number of publishers (default 4)
#   N           number of subscribers (default 4)
#   PER         messages per publisher (default 200000)
#   SIZE        payload bytes (default 64)
#
# The broker is pinned to one core (single event-loop thread => per-core
# capacity). Timing covers the parallel publisher burst; each publisher drains
# to the broker before exiting, and the broker throttles via TCP backpressure,
# so wall time reflects ingest+route+deliver capacity. Prints ingress msg/s.
#
# To compare two builds, run this alternately against two named binaries and
# average; do not run all of one then all of the other (see README.md).
set -u
BIN=${1:?usage: multibench.sh BROKER_BIN [M] [N] [PER] [SIZE]}
M=${2:-4}; N=${3:-4}; PER=${4:-200000}; SIZE=${5:-64}
HERE=$(cd "$(dirname "$0")" && pwd)
PUB="$HERE/mqtt_throughput_pub"
PORT=1888; TOPIC=bench/topic; TOTAL=$((M*PER))
CONF=$(mktemp); printf 'listener %d\nallow_anonymous true\nmax_queued_messages 1000000\n' "$PORT" >"$CONF"

taskset -c 2 "$BIN" -c "$CONF" >/dev/null 2>&1 &
BPID=$!; sleep 0.8
spids=()
for i in $(seq 0 $((N-1))); do
	mosquitto_sub -p $PORT -t "$TOPIC" -q 0 >/dev/null 2>&1 &
	spids+=($!)
done
sleep 1.2
ppids=()
t0=$(date +%s.%N)
for i in $(seq 0 $((M-1))); do
	"$PUB" $PORT "$PER" "$SIZE" "$TOPIC" >/dev/null 2>&1 &
	ppids+=($!)
done
for p in "${ppids[@]}"; do wait "$p"; done
t1=$(date +%s.%N)
for p in "${spids[@]}"; do kill "$p" 2>/dev/null; done
kill $BPID 2>/dev/null; wait 2>/dev/null
rm -f "$CONF"
awk "BEGIN{printf \"M=%d N=%d %dx%dB: %.0f ingress msg/s\n\",$M,$N,$PER,$SIZE,$TOTAL/($t1-$t0)}"
