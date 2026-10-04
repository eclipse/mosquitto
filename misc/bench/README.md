# Broker throughput benchmark

A small harness for measuring broker message throughput, used to substantiate
performance changes such as the EPOLLOUT-toggle removal in `packet__write()`.

## Contents
- `mqtt_throughput_pub.c` — single-connection QoS-0 publisher that reports the
  achieved publish rate.
- `multibench.sh` — drives `M` publishers and `N` subscribers on one topic and
  reports aggregate ingress rate.

## Build
```
cc -O2 mqtt_throughput_pub.c -lmosquitto -o mqtt_throughput_pub
```

## Single publisher / single subscriber
```
mosquitto -c broker.conf &                 # listener on 1883, allow_anonymous
mosquitto_sub -t bench/topic -q 0 -C 3000000 >/dev/null &
./mqtt_throughput_pub 1883 3000000 64 bench/topic
```

## Multiple publishers / subscribers
```
./multibench.sh /path/to/mosquitto 4 4 200000 64   # 4 pub, 4 sub, 200k each
```

## Measuring a change correctly
Absolute throughput on virtualised / shared hosts drifts significantly between
runs, so an A/B comparison must control for it:

1. Build **two named binaries** from the two revisions and confirm they differ
   (`md5sum`). Do not rely on `git stash` + `make`: on a branch where the change
   is already committed the stash is a no-op, and `make` may skip recompiling on
   a stale object timestamp — yielding two identical binaries.
2. **Interleave** trials (baseline, patched, baseline, patched, …) rather than
   running all of one then all of the other, so host drift affects both equally.
3. Prefer a **deterministic** signal where possible. For the EPOLLOUT change,
   `strace -c -e epoll_ctl` on the broker over a fixed message count is immune to
   timing noise:

   | build    | epoll_ctl / 200k msgs |
   |----------|-----------------------|
   | before   | ~334,000 (~1.67/msg)  |
   | after    | ~0                    |

Pin the broker to a dedicated core (`taskset -c`) to reduce scheduler noise;
the broker runs a single event-loop thread, so this measures per-core capacity.
