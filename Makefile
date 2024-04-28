VERSION=1.0

DEBUG=-g -pedantic #-pg #-fprofile-arcs
LDFLAGS=-lssl -lcrypto -lm -lsnmp $(DEBUG) -flto
CFLAGS+=-O2 -Wall -DVERSION=\"$(VERSION)\" $(DEBUG) -flto

OBJS=error.o log.o utils.o utils2.o daytime.o time.o mssl.o http.o snts.o irc.o icmp.o ntpd.o snmp.o simpleptp.o socks5sntp.o main.o sntp.o

all: omnisync

omnisync: $(OBJS)
	$(CC) -Wall $(OBJS) $(LDFLAGS) -o omnisync

install: omnisync
	cp omnisync $(DESTDIR)/usr/local/sbin

uninstall: clean
	rm -f $(DESTDIR)/usr/local/sbin/omnisync

clean:
	rm -f $(OBJS) omnisync core gmon.out *.da

package: clean
	# source package
	rm -rf omnisync-$(VERSION)*
	mkdir omnisync-$(VERSION)
	cp *.c *.h *akefile* readme.txt Changes license.txt omnisync-$(VERSION)
	tar czf omnisync-$(VERSION).tgz omnisync-$(VERSION)
	rm -rf omnisync-$(VERSION)
