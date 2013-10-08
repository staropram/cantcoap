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
		INFO("Error setting up remote address, exiting.");
		return -1;
	}

	// call connect to associate remote address with socket
	ret = connect(sockfd,remoteAddress->ai_addr,remoteAddress->ai_addrlen);
	if(ret!=0) {
		INFO("Error: %s.",gai_strerror(ret));
		INFO("Error connecting to remote host.");
		return -1;
	}
	printAddress(remoteAddress);

	// construct CoAP packet
	CoapPDU *pdu = new CoapPDU();
	pdu->setVersion(1);
	pdu->setType(CoapPDU::COAP_CONFIRMABLE);
	pdu->setCode(CoapPDU::COAP_GET);
	pdu->setToken((uint8_t*)"\3\2\1\1",4);
	pdu->setMessageID(0x0005);
	pdu->setURI((char*)"test",4);
	pdu->addOption(CoapPDU::COAP_OPTION_CONTENT_FORMAT,1,(uint8_t*)")");

	// send packet
	ret = send(sockfd,pdu->getPDUPointer(),pdu->getPDULength(),0);
	if(ret!=pdu->getPDULength()) {
		INFO("Error sending packet.");
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

	// validate packet
	CoapPDU *recvPDU = new CoapPDU((uint8_t*)buffer,ret);
	if(recvPDU->validate()!=1) {
		INFO("Malformed CoAP packet");
		return -1;
	}
	INFO("Valid CoAP PDU received");
	recvPDU->printHuman();
	
	return 0;
}

