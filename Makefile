CPPFLAGS=-Wall -lcunit
default: test

test: cantcoap.o

cantcoap: cantcoap.h

clean:
	rm *.o;
