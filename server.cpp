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
	if(argc!=3) {
		printf("USAGE\r\n   %s listenAddress listenPort\r\n",argv[0]);
		return 0;
	}

	char *listenAddressString = argv[1];
	char *listenPortString    = argv[2];

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


	// temporary
	#define BUF_LEN 500
	char buffer[BUF_LEN];
	sockaddr recvAddr;
	socklen_t recvAddrLen;
	CoapPDU *recvPDU = NULL;

	// just block completely
	while(1) {
		// receive packet
		ret = recvfrom(sockfd,&buffer,BUF_LEN,0,&recvAddr,&recvAddrLen);
		if(ret==-1) {
			INFO("Error receiving data");
			return -1;
		}

		// validate packet
		recvPDU = new CoapPDU((uint8_t*)buffer,ret);
		if(recvPDU->isValid()!=1) {
			INFO("Malformed CoAP packet");
			delete recvPDU;
			continue;
		}
		INFO("Valid CoAP PDU received");
		recvPDU->printHuman();
		delete recvPDU;
	}
	
	return 0;
}

