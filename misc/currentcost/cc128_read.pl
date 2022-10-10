#!/usr/bin/perl -w

# Reads data from a Current Cost device via serial port.
# Spawns

use strict;
use Device::SerialPort qw( :PARAM :STAT 0.07 );

my $pubclient = "mosquitto_pub -t sensors/cc128/raw -q 1 -l";
my $PORT = "/dev/ttyUSB0";
local $| = 1;

my $ob = Device::SerialPort->new($PORT);
$ob->baudrate(57600);
$ob->write_settings;

open(SERIAL, "+<$PORT");
open(MQTT, "|$pubclient");
while (my $line = <SERIAL>) {
	print(MQTT "$line");
}

close(MQTT);
