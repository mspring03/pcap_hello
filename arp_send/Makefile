all : arp_send

arp_send: arpsend.o main.o
	g++ -g -o arp_send arpsend.o main.o -lpcap

main.o:
	g++ -g -c -o main.o main.cpp

packet.o:
	g++ -g -c -o packet.o packet.cpp
	
arpsend.o:
	g++ -g -c -o arpsend.o arpsend.cpp

clean:
	rm -f arp_send
	rm -f *.o
