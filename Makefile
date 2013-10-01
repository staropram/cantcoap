CC="gcc"
CPPFLAGS=-Wall -L/usr/lib -std=c99 
default: test client

test: cantcoap.o nethelper.o -lcunit

COAP_OBJS=cantcoap.h cantcoap.cpp

cantcoap: $(COAP_OBJS)

client: cantcoap.o nethelper.o client.cpp


clean:
	rm *.o;
