
all: pcap-test

pcap-test: pcap-test.c
	gcc -o pcap-test pcap-test.c -lpcap

