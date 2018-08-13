all: ARP_test

ARP_test: main.o
	g++ -g -o ARP_test main.o -lpcap

main.o:
	g++ -g -c -o main.o main.cpp

clean:
	rm -f ARP_test
	rm -f *.o

