LIB_EXTERNAL=-L/usr/local/lib/event2 -L$(HOME)/lib
INCLUDE_EXTERNAL=-I/usr/local/include/event2 -I/$(HOME)/include

LIBS=$(LIB_EXTERNAL) -levent -ltinydtls
CFLAGS=-Wall -g -Wincompatible-pointer-types-discards-qualifiers
INCLUDE=$(INCLUDE_EXTERNAL) -I./include  -L./
CXX=clang++
default: dtls_server dtls_client

dtls_server: dtls_server.c ../../libcantcoap.a ../../nethelper.o
	$(CXX) $(CFLAGS) $(INCLUDE) $^ $(LIBS) -o $@

dtls_client: dtls_client.c ../../libcantcoap.a ../../nethelper.o
	$(CXX) $(CFLAGS) $(INCLUDE) $^ $(LIBS) -o $@

%.o : %.c
	$(CXX) $< $(CFLAGS) $(INCLUDE) -c -o $@

clean:
	rm *.o; rm dtls_server; rm dtls_client;
