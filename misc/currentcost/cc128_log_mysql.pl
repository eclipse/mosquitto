#!/usr/bin/perl

# Log CurrentCost power meter data to a mysql database.
# Assumes data is coming in on MQTT topic sensors/cc128
# and in format timestamp,temperature,ch1_data
# e.g. 1276605752,12.7,86

# To create database, table and user:
#
# CREATE DATABASE powermeter;
# USE 'powermeter';
# CREATE TABLE powermeter (
#   `id` INT NOT NULL auto_increment,
#   `timestamp` INT NOT NULL,
#   `temperature` FLOAT NOT NULL DEFAULT 0.0,
#   `ch1` INT NOT NULL DEFAULT 0,
#   PRIMARY KEY (`id`),
#   UNIQUE KEY `timestamp` (`timestamp`)
# ) ENGINE=InnoDB DEFAULT CHARSET=utf8;
#
# CREATE USER 'powermeter'@'localhost' IDENTIFIED BY '<your password>';
# GRANT ALL ON powermeter.* to 'powermeter'@'localhost';

use strict;
use DBI();
use FileHandle;

local $| = 1;

my $dbname = "powermeter";
my $dbhost = "localhost";
my $dbusername = "powermeter";
my $dbpassword = "<your password>";
my $dbtable = "powermeter";

my $subclient = "mosquitto_sub -t sensors/cc128";
open(SUB, "$subclient|");
SUB->autoflush(1);

my $dbh = DBI->connect("DBI:mysql:database=$dbname;host=$dbhost",
		"$dbusername", "$dbpassword", {'RaiseError' => 1});

my $query = "INSERT INTO powermeter (timestamp, temperature, ch1) VALUES (?,?,?)";

my @vals;
my ($timestamp, $temperature, $ch1);
while (my $line = <SUB>) {
	@vals = split(/,/, $line);
	$timestamp = @vals[0];
	$temperature = @vals[1];
	$ch1 = @vals[2];
	$dbh->do($query, undef, $timestamp, $temperature, $ch1);
}
$dbh->disconnect();

