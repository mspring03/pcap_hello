all : pcap_hello

pcap_hello: http.o packet.o main.o
	g++ -g -o pcap_hello packet.o http.o main.o -lpcap

main.o:
	g++ -g -c -o main.o main.cpp

packet.o:
	g++ -g -c -o packet.o packet.cpp

http.o:
	g++ -g -c -o http.o http.cpp

clean:
	rm -f pcap_hello
	rm -f *.o
