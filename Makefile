CC="gcc"
CPPFLAGS=-Wall -lcunit -std=c99 #-DDEBUG
default: test client

test: cantcoap.o nethelper.o

COAP_OBJS=cantcoap.h cantcoap.cpp

cantcoap: $(COAP_OBJS)

client: cantcoap.o nethelper.o client.cpp


clean:
	rm *.o;
