all : pcap_test

pcap_test:
		g++ -g -o main.o main.cpp -lpcap

clean:
		rm -f pcap_test
		rm -f