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
#include "uthash.h"

//void callback(char *uri, method);

///////////// Begin Resource Stuff ///////////////
// call backs and some other crap for mapping URIs
// you might be thinking, huh, why not make a dynamic
// way to construct this, and that might make sense
// for a high performance machine, but on an embedded
// device you really don't want all these strings in RAM

typedef int (*ResourceCallback)(CoapPDU *pdu);

// using uthash for the URI hash table. Each entry contains a callback handler.
struct URIHashEntry {
    const char *uri; 
	 ResourceCallback callback;
    int id;
    UT_hash_handle hh;
};

// callback functions defined here
int gTestCallback(CoapPDU *p) {
	DBG("gTestCallback function called");
	return 1;
}

// resource URIs here
const char *gURIA = "/test";

const char *gURIList[] = {
	gURIA,
};

// URIs mapped to callback functions here
const ResourceCallback gCallbacks[] = {
	gTestCallback	
};

const int gNumResources = 1;

///////////// End Resource Stuff //////////////

// for mbed compatibility
#define failGracefully exit

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

	// setup URI callbacks using uthash hash table
	struct URIHashEntry *entry = NULL, *directory = NULL, *hash = NULL;
	for(int i=0; i<gNumResources; i++) {
		// create new hash structure to bind URI and callback
   	entry = (struct URIHashEntry*)malloc(sizeof(struct URIHashEntry));
		entry->uri = gURIList[i];
		entry->callback = gCallbacks[i];
		// add hash structure to hash table, note that key is the URI
   	HASH_ADD_KEYPTR(hh, directory, entry->uri, strlen(entry->uri), entry);
	}

	// temporary
	#define BUF_LEN 500
	char buffer[BUF_LEN];
	sockaddr recvAddr;
	socklen_t recvAddrLen;
	CoapPDU *recvPDU = NULL;
	#define URI_BUF_LEN 32
	char uriBuffer[URI_BUF_LEN];
	int recvURILen = 0;

	// just block completely since this is only an example
	// you're not going to use this for a production system are you ;)
	while(1) {
		// receive packet
		ret = recvfrom(sockfd,&buffer,BUF_LEN,0,&recvAddr,&recvAddrLen);
		if(ret==-1) {
			INFO("Error receiving data");
			return -1;
		}


/*
		// try to get hostname and service
		if(getnameinfo((struct sockaddr*)&fromAddr,fromAddrLen,hostStr,hostStrLen,servStr,servStrLen,0)==0) {
			INFO("Received %ld bytes from %s:%s",ret,hostStr,servStr);
		} else {
			INFO("Received %ld bytes from %s:%d",ret,inet_ntoa(fromAddr.sin_addr),ntohs(fromAddr.sin_port));
		}
		*/


		// validate packet
		recvPDU = new CoapPDU((uint8_t*)buffer,ret);
		if(recvPDU->isValid()!=1) {
			INFO("Malformed CoAP packet");
			delete recvPDU;
			continue;
		}
		INFO("Valid CoAP PDU received");
		recvPDU->printHuman();

		// depending on what this is, maybe call callback function
		if(recvPDU->getURI(uriBuffer,URI_BUF_LEN,&recvURILen)!=0) {
			INFO("Error retrieving URI");
			continue;
		}
		if(recvURILen==0) {
			INFO("There is no URI associated with this Coap PDU");
		} else {
			HASH_FIND_STR(directory,uriBuffer,hash);
			if(hash) {
				DBG("Hash id is %d.", hash->id);
				hash->callback(recvPDU);
			} else {
				DBG("Hash not found.");
				continue;
			}
		}
		

		delete recvPDU;
	}

    // free the hash table contents
	 /*
    HASH_ITER(hh, users, s, tmp) {
      HASH_DEL(users, s);
      free(s);
    }
	 */
	
	return 0;
}

