rm test.json
export MOSQUITTO_DYNSEC_PASSWORD=passwordpass
export VG="valgrind --log-file=vglog"
${VG} ../../src/mosquitto -c test.conf
