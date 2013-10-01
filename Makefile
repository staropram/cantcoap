CC="gcc"
LIBS=-L/usr/local/lib
INCLUDE=-I/usr/local/include
CPPFLAGS=-Wall -lcunit -std=c99 $(LIBS) $(INCLUDE) #-DDEBUG
CFLAGS=-Wall -lcunit -std=c99 $(LIBS) $(INCLUDE)
default: test client

test: cantcoap.o nethelper.o

COAP_OBJS=cantcoap.h cantcoap.cpp

cantcoap: $(COAP_OBJS)

client: cantcoap.o nethelper.o client.cpp


clean:
	rm *.o;
