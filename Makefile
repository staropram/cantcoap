LIB_INSTALL=$(HOME)/lib
INCLUDE_INSTALL=$(HOME)/include

CURDIR=/opt/local/lib -L.
TEST_LIBS=-L$(CURDIR) -lcunit

CPPFLAGS=-DDEBUG -I/opt/local/include
CFLAGS=-Wall -std=c99
CXXFLAGS=-Wall -std=c++11

default: nethelper.o staticlib test

test: test.cpp libcantcoap.a
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $< -o $@ -lcantcoap $(TEST_LIBS)

cantcoap.o: cantcoap.cpp cantcoap.h
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $< -c -o $@

nethelper.o: nethelper.c nethelper.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -c -o $@

staticlib: libcantcoap.a

libcantcoap.a: cantcoap.o
	$(AR) $(ARFLAGS) libcantcoap.a $^

clean:
	$(RM) *.o test libcantcoap.a

install:
	install libcantcoap.a $(LIB_INSTALL)/
	install cantcoap.h $(INCLUDE_INSTALL)/
