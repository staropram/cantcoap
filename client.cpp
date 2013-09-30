// simple client example for cantcoap
#include <sys/types.h>
#include <sys/socket.h>
#define __USE_POSIX 1
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/time.h>
#include <math.h>
#include "nethelper.h"
#include "cantcoap.h"

#define INFO(...) printf(__VA_ARGS__); printf("\r\n")
#define ERR(...) printf(__VA_ARGS__); printf("\r\n")

#define DEBUG 1

#ifdef DEBUG
	#define DBG(...) fprintf(stderr,__VA_ARGS__); fprintf(stderr,"\r\n")
	#define DBGX(...) fprintf(stderr,__VA_ARGS__);
#else
	#define DBG(...) {};
	#define DBGX(...) {};
#endif

void failGracefully(int x) {
	exit(x);
}

int main(int argc, char **argv) {

	// parse options	
	if(argc!=5) {
		printf("USAGE\r\n   %s listenAddress listenPort remoteAddress remotePort\r\n",argv[0]);
		return 0;
	}

	char *listenAddressString = argv[1];
	char *listenPortString    = argv[2];
	char *remoteAddressString = argv[3];
	char *remotePortString    = argv[4];

	// setup bind address
	struct addrinfo *bindAddr;
	INFO("Setting up bind address");
	int ret = setupAddress(listenAddressString,listenPortString,&bindAddr,SOCK_DGRAM,AF_INET);
	if(ret!=0) {
		INFO("Error setting up bind address, exiting.");
		return -1;
	}

	// iterate through returned structure to see what we got
	printAddressStructures(bindAddr);

	// setup socket
	int sockfd = socket(bindAddr->ai_family,bindAddr->ai_socktype,bindAddr->ai_protocol);

	// call bind
	DBG("Binding socket.");
	if(bind(sockfd,bindAddr->ai_addr,bindAddr->ai_addrlen)!=0) {
		DBG("Error binding socket");
		perror(NULL);
		failGracefully(5);
	}
	
	//
	printAddress(bindAddr);


	struct addrinfo *remoteAddress;
	ret = setupAddress(remoteAddressString,remotePortString,&remoteAddress,SOCK_DGRAM,AF_INET);
	if(ret!=0) {
		INFO("Error setting up bind address, exiting.");
		return -1;
	}

	// call connect to associate remote address with socket
	ret = connect(sockfd,remoteAddress->ai_addr,remoteAddress->ai_addrlen);
	if(ret!=0) {
		INFO("Error connecting to remote host.");
		return -1;
	}
	printAddress(remoteAddress);

	// construct CoAP packet
	CoapPDU *pdu = new CoapPDU();
	pdu->setVersion(1);
	pdu->setType(CoapPDU::COAP_CONFIRMABLE);
	pdu->setCode(CoapPDU::COAP_GET);
	pdu->setToken((uint8_t*)"\3\2\1\0",4);
	pdu->addOption(11,3,(uint8_t*)"oma");
	pdu->addOption(11,8,(uint8_t*)"firmware");

	// send packet to self
	ret = send(sockfd,pdu->getPDU(),pdu->getPDULength(),0);
	if(ret!=pdu->getPDULength()) {
		INFO("Error sending packet to self.");
		perror(NULL);
		return -1;
	}
	INFO("Packet sent");

	// receive packet
	char buffer[500];
	ret = recv(sockfd,&buffer,500,0);
	if(ret==-1) {
		INFO("Error receiving data");
		return -1;
	}
	buffer[ret] = 0x00;
	INFO("Received %d bytes: \"%s\"",ret,buffer);

	// validate packet
	CoapPDU *recvPDU = new CoapPDU(buffer);
	if(recvPDU==NULL) {
		INFO("Malformed CoAP packet");
		return -1;
	}
	
	
	return 0;
}

