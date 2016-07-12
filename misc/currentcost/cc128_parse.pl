#!/usr/bin/perl -w

# Read raw cc128 data and republish without xml.
# Probably only works if you have a single channel.

use strict;
use HTTP::Date "str2time";
use FileHandle;

local $| = 1;

my $subclient = "mosquitto_sub -t sensors/cc128/raw -q 1";
my $pubclient = "mosquitto_pub -t sensors/cc128 -q 1 -l";
my $pubclient_ch1 = "mosquitto_pub -t sensors/cc128/ch1 -q 1 -l";

open(SUB, "$subclient|");
open(PUB, "|$pubclient");
open(PUB_CH1, "|$pubclient_ch1");

SUB->autoflush(1);
PUB->autoflush(1);
PUB_CH1->autoflush(1);

while (my $line = <SUB>) {
	#<msg><src>CC128-v0.12</src><dsb>00002</dsb><time>00:02:12</time><tmpr>15.7</tmpr><sensor>0</sensor><id>03112</id><type>1</type><ch1><watts>00108</watts></ch1></msg>
	if ($line =~ m#<time>(.*)</time><tmpr> *([\-\d.]+)</tmpr><sensor>0</sensor><id>[0-9]*</id><type>1</type><ch1><watts>0*(\d+)</watts></ch1></msg.*#){
		my $reading_time = $1;
		my $temp = $2;
		my $watts = $3;

		my $now = time;
		my ($sec,$min,$hour,$mday,$month,$year,$wday,$yday,$isdst,$r_stamp);

		($sec,$min,$hour,$mday,$month,$year,$wday,$yday,$isdst) = localtime($now);
		$year += 1900;
		$month += 1;
		$r_stamp = str2time("$year-$month-$mday $reading_time");
		if($r_stamp > $now){
			$r_stamp -= 86400;
		}

		print PUB "$r_stamp,$temp,$watts\n";
		print PUB_CH1 "$r_stamp $watts\n";
	}
}
