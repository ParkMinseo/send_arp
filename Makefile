all: SendARP

SendARP: main.o
	g++ -o SendARP main.o -lpcap

main.o: main.cpp
	g++ -c -o main.o main.cpp

clean:
	rm -f *.o
	rm -f SendARP
