CC="gcc"
LIBS=-L/usr/local/lib
INCLUDE=-I/usr/local/include
CPPFLAGS=-Wall -std=c99 $(LIBS) $(INCLUDE) -DDEBUG
default: test client server

test: cantcoap.o nethelper.o cantcoap.h -lcunit

COAP_OBJS=cantcoap.h cantcoap.cpp

cantcoap: $(COAP_OBJS)

client: cantcoap.o nethelper.o client.cpp

server: cantcoap.o nethelper.o server.cpp

clean:
	rm *.o;
