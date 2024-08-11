all: arp_spoofing

arp_spoofing: main1.cpp header.h
	g++ -o arp_spoofing main1.cpp -lpcap

clean:
	rm -f arp_spoofing
