#!/usr/bin/python -u

import mosquitto
import serial

usb = serial.Serial(port='/dev/ttyUSB0', baudrate=57600)

mosq = mosquitto.Mosquitto()
mosq.connect("localhost")
mosq.loop_start()

running = True
try:
    while running:
        line = usb.readline()
        mosq.publish("sensors/cc128/raw", line)
except usb.SerialException, e:
    running = False

mosq.disconnect()
mosq.loop_stop()

