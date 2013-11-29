LIB_INSTALL=~/lib
INCLUDE_INSTALL=~/include

LIBS=-L/usr/local/lib -lcunit
INCLUDE=-I/usr/local/include

#CXX=g++49
CXX=clang++
CXXFLAGS=-Wall -DDEBUG -std=c++11 $(LIBS) $(INCLUDE)

#CC=gcc49
CC=clang
CFLAGS=-Wall -std=c99 -DDEBUG

default: nethelper.o staticlib test

test: libcantcoap.a test.cpp

cantcoap.o: cantcoap.cpp

nethelper.o: nethelper.c
	$(CC) $(CFLAGS) $(INCLUDE) $(LIBS) -c $^ -o $@

staticlib: libcantcoap.a

libcantcoap.a: cantcoap.o
	ar -rc libcantcoap.a $^

clean:
	rm *.o; rm test; rm libcantcoap.a

install:
	cp libcantcoap.a $(LIB_INSTALL)/
	cp cantcoap.h $(INCLUDE_INSTALL)/
