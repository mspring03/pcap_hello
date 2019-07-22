all : pcap_hello

pcap_hello: main.o
	g++ -g -o pcap_hello main.o -lpcap

main.o:
	g++ -g -c -o main.o main.cpp

clean:
	rm -f pcap_hello
	rm -f *.o
