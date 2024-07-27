CC=gcc
CFLAGS=-Wall -O2
LDFLAGS=-lpcap

all: pcap-test

pcap-test: pcap-test.c
	$(CC) $(CFLAGS) -o pcap-test pcap-test.c $(LDFLAGS)

clean:
	rm -f pcap-test
