This is a simple example of the C++ library mosquittopp.

It is a client that subscribes to the topic temperature/celsius which should
have temperature data in text form being published to it. It reads this data as
a Celsius temperature, converts to Fahrenheit and republishes on
temperature/fahrenheit.
