LIB_EXTERNAL=-L/usr/local/lib/event2 -L/home/ash/lib
INCLUDE_EXTERNAL=-I/usr/local/include/event2 -I/home/ash/include

LIBS=$(LIB_EXTERNAL) -lc++ -levent -ltinydtls
CFLAGS=-Wall -g -Wincompatible-pointer-types-discards-qualifiers
INCLUDE=$(INCLUDE_EXTERNAL) -I./include  -L./
CXX=clang++
default: dtls_server

dtls_server: ../../nethelper.o dtls_server.c 
	$(CXX) $(CFLAGS) $(INCLUDE) $^ $(LIBS) -o $@

%.o : %.c
	$(CXX) $< $(CFLAGS) $(INCLUDE) -c -o $@

clean:
	rm *.o; rm dtls_server; 
