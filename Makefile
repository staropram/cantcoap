LIBS=-L/usr/local/lib -lcunit
INCLUDE=-I/usr/local/include

CXX=clang++
CXXFLAGS=-Wall -DDEBUG -std=c++11 $(LIBS) $(INCLUDE)

CC=clang
CFLAGS=-Wall -std=c99 -DDEBUG

default: test client server

test: cantcoap.o nethelper.o test.cpp

client: cantcoap.o nethelper.o client.cpp

server: cantcoap.o nethelper.o server.cpp

cantcoap.o: cantcoap.cpp

nethelper.o: nethelper.c
	$(CC) $(CFLAGS) $(INCLUDE) $(LIBS) -c $^ -o $@

clean:
	rm *.o; rm test; rm server; rm client;
