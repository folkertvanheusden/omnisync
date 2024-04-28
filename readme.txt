Building:
--------
make install

on IRIX:
gmake -f makefile.irix install

It requires net-snmp and openssl development files.


Running:
-------
Run:
omnisync --help
for a complete list of commandline switches.

Example:
omnisync -m daytime/udp -h 192.168.0.1 -u 0 -f -v

This runs omnisync in foreground mode (e.g. it does not become a daemon process) and using the "daytime" service it syncs against the host at ip address 192.168.0.1.
It uses in this example shared memory block 0 ("-u 0").


Configuring ntpd:
----------------
Add the following 2 lines to your ntp.conf file:
# use shared memory block 0
server 127.127.28.0
# use shared memory block 1 (too)
# server 127.127.28.1
# and 2
# server 127.127.28.2
# etc.
# server 127.127.28.3

More help:
---------
Invoke:
omnisync -h


Syncing against multiple sources:
--------------------------------
add the following to /etc/ntp.conf:
	server 127.127.28.0
	server 127.127.28.1
	server 127.127.28.2
	server 127.127.28.3
invoke omnisync 4 times:
	omnisync -m http -h host1 -u 0 -f -v
	omnisync -m http -h host2 -u 1 -f -v
	omnisync -m http -h host3 -u 2 -f -v
	omnisync -m http -h host4 -u 3 -f -v
replace 'host1'...'host4' with the hostnames of 4 different http servers.

Of course one can, using this method, sync via multiple protocols. E.g. 2 http servers, a daytime and an irc server.


Syncing against more then 4 sources:
-----------------------------------
For that one needs to change the NTPd sources.


What to use:
-----------
Is icmp available? (e.g. can you ping a host with a good clock) Then consider using that as it has ms resolution.


Notes:
-----
The snmp sync code requests the 'HOST-RESOURCES-MIB::hrSystemDate.0' variable. That is not supported by all devices it seems. If not, you'll get an error.


by folkert van heusden <folkert@vanheusden.com>
