@mainpage

Doxygen generated docs are here: [http://staropram.github.io/cantcoap/index.html](http://staropram.github.io/cantcoap/index.html)

cantcoap
========

CoAP implementation that focuses on simplicity by offering a minimal set of functions and straightforward interface.

~~~{.cpp}
	CoapPDU *pdu = new CoapPDU();
	pdu->setType(CoapPDU::COAP_CONFIRMABLE);
	pdu->setCode(CoapPDU::COAP_GET);
	pdu->setToken((uint8_t*)"\3\2\1\0",4);
	pdu->setMessageID(0x0005);
	pdu->setURI((char*)"test",4);

	// send packet 
	ret = send(sockfd,pdu->getPDUPointer(),pdu->getPDULength(),0);
~~~

...

~~~{.cpp}
	// receive packet
	ret = recvfrom(sockfd,&buffer,BUF_LEN,0,(sockaddr*)&recvAddr,&recvAddrLen);
	CoapPDU *recvPDU = new CoapPDU((uint8_t*)buffer,ret);
	if(recvPDU->validate()) {
		recvPDU->getURI(uriBuffer,URI_BUF_LEN,&recvURILen);
		...
	}
~~~

# Compilation

## Dependencies

### CUnit 

See: http://cunit.sourceforge.net/

This is a testing framework for c. 
On Debian based Linux you need libcunit1 and libcunit1-dev

#### Debian (Ubuntu, Mint etc...)

\#apt-get update && apt-get install libcunit1 libcunit1-dev

Or for newbie types:

$sudo apt-get update

$sudo apt-get install libcunit1 libcunit1-dev


#### SuSE Linux - openSUSE 12.1 (x86_64)

Note there is different package naming convention here for packages.

$sudo zypper install libcunit-dev

$sudo zypper install cunit-devel

#### BSD 

Probably some variation, but for FreeBSD, CUnit is in the ports collection at /usr/ports/devel/cunit.

## Build

Type make (Note, build with GNU make on BSD). This builds the test framework too. Type ./test to feel some misplaced confidence.

There is also an example client and server made. The server is supposed to work with the website coap.me, but isn't finished.

# Long description

This is a CoAP implementation with a focus on simplicity. The library only provides PDU construction and de-construction.

The user is expected to deal with retransmissions, timeouts, and message ID matching themselves. This isn’t as arduous as it sounds and makes a lot more sense on a constrained device.

Imagine for example a simple microcontroller sensor that only reports readings once every 15 minutes, and only sends a few packets each time. Do you really need a complicated framework to deal with acknowledgements and re-transmissions?

Since CoAP recommends you only send one packet at at time, this means you only need to keep track of one on-going transaction at a time. Yeah... I think you’re capable of this.

Furthermore, the timers and interrupt processes between different embedded processor architectures, vary quite a bit. So it often makes sense to write the packet sending processes yourself.

Finally, you might be sending the packets over odd transport bearers such as a SMS (woah dude, that's just totally wild) or a simple radio bearer. In which case, it’s easiest to deal with buffers. If I built retransmission handlers, they’d all be UDP/IP specific and would bloat the code for no reason.

# Examples

## Construction

There are a couple of different ways to construct a PDU depending on whether you want the library to allocate memory for you, or whether you have an external buffer you want to use. You can also re-purpose existing objects.

### Using a managed object

The simplest usage scenario hands control of memory allocation to the library:

~~~{.cpp}
CoapPDU *pdu = new CoapPDU();
...
pdu->setType(CoapPDU::COAP_CONFIRMABLE);
pdu->setCode(CoapPDU::COAP_GET);
pdu->addOption(11,5,(uint8_t*)"hello");
pdu->addOption(11,5,(uint8_t*)"there");
pdu->addOption(11,6,(uint8_t*)"server");
~~~

In this case you just call the default constructor. That's it. The library handles memory from there-on out. For example, when adding each of those options, the library will realloc the pdu to accomodate space for them. It will also shrink the PDU if something changes (like the token length) so that it always uses the minimum amount of memory.

When you free the PDU, all data including the buffer is deleted. The PDU can also be reused as shown below.

### Using an external buffer for memory

There are two obvious reasons why you would do this:

1. The buffer contains a CoAP PDU and you want to access the data in the PDU.
2. Buffers cost space and allocating memory consumes processor resources. On embedded targets it is often simpler to reuse buffers where possible.

The first instance is a special case and requires some extra work. Just using an external buffer is as simple as follows:

~~~{.cpp}
uint8_t *buffer[100];
CoapPDU *pdu = new CoapPDU((uint8_t*)buffer,100,0);
...
pdu->setType(CoapPDU::COAP_CONFIRMABLE);
pdu->setCode(CoapPDU::COAP_GET);
pdu->addOption(11,5,(uint8_t*)"hello");
pdu->addOption(11,5,(uint8_t*)"there");
pdu->addOption(11,6,(uint8_t*)"server");
~~~

The PDU is constructed as normal except that the memory of your buffer is used instead of allocated memory.

A call such as this:

~~~{.cpp}
pdu->addOption(11,5,(uint8_t*)"hello");
~~~

Will fail if there is no space left in the buffer.

When you delete the object, the buffer is not freed. Hey, it's your buffer mannn!

### Reusing an existing object

Regardless of whether you constructed a PDU using either of the above methods, you can always reuse it:

~~~{.cpp}
pdu->reset(); 
...
pdu->setType(CoapPDU::COAP_CONFIRMABLE);
pdu->setCode(CoapPDU::COAP_GET);
pdu->addOption(11,5,(uint8_t*)"hello");
pdu->addOption(11,5,(uint8_t*)"there");
pdu->addOption(11,6,(uint8_t*)"server");
~~~

The only difference is that if the PDU was initially constructed using managed-memory, then it will continue to have managed-memory. Whereas if the PDU was constructed with an external buffer, then you are limited in space by the size of the buffer you used.

## Receving CoAP packets over a network or something

In this case you have a CoAP PDU in a buffer you just gobbled from a socket and want to read it:

	
~~~{.cpp}
uint8_t *buffer[100];
int ret = recvfrom(sockfd,&buffer,BUF_LEN,0,(sockaddr*)&recvAddr,&recvAddrLen);
CoapPDU *recvPDU = new CoapPDU((uint8_t*)buffer,ret,100);
if(recvPDU->validate()) {
	recvPDU->printHuman();
	// do your work
}
~~~

You must call CoapPDU::validate() and get a positive response before accessing any of the data members. This sets up some internal pointers and so on, so if you fail to do it, undefined behaviour will result.

Note that the constructor is just a shorthand for the external-buffer-constructor explained above, and you can use the long form if you want. For example. you might want to use the long form if you have a buffer bigger than the PDU and you expect to reuse it.

You can reuse this object by resetting it as above.

If you reuse such an object, you need to set the PDU length manually because there is no way to deduce the PDU length using validate():

~~~{.cpp}
	// earlier
	#define BUFLEN 500
	char buffer[BUFLEN];
	CoapPDU *recvPDU = new CoapPDU((uint8_t*)buffer,BUFLEN,BUFLEN);

	...

	while(1) {
		// receive packet
		ret = sockfd,&buffer,BUFLEN,0);
		if(ret==-1) {
			INFO("Error receiving data");
			// handle error
		}

		// validate packet
		// you should also check that ret doesn't exceed buffer length
		recvPDU->setPDULength(ret);
		if(recvPDU->validate()!=1) {
			INFO("Malformed CoAP packet");
			// handle error
		}
	}
~~~
