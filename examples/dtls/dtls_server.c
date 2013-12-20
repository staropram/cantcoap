#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#define __USE_POSIX 1
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <sys/socket.h>
#include <fcntl.h>

#include <assert.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

// libevent
#include <event2/event.h>

// tinydtls
#include "tinydtls/config.h"
extern "C" {
#include "tinydtls/dtls.h"
#include "tinydtls/debug.h"
}

// helpers
#include "../../nethelper.h"
#include "../../dbg.h"

// coap
#include "../../cantcoap.h"

// globals

///////// DTLS STUFF
dtls_context_t *g_dtls_context = NULL;
#define DTLS_SERVER_CMD_CLOSE "server:close"
#define DTLS_SERVER_CMD_RENEGOTIATE "server:renegotiate"

/**
 * DTLS key management callback.
 * This function is used to manage the pre-shared keys and identities used to authenticate self to others and others to self.
 * It has two invocations by tinydtls:
 *
 * 1. We are acting as a server, a client has connected to us and we need to send it our ID
 *    In this case tinydtls asks for our identity by setting id to NULL.
 * 2. We are a client conneting to a server, the client has identified itself with an ID
 *    and we need to tell tinydtls which key to use with this peer.
 */
int tinydtls_getpsk_callback(
	struct dtls_context_t *ctx,
	const session_t *session,
	const unsigned char *id,
	size_t id_len,
	const dtls_psk_key_t **result) {

	DBG("Been asked to get PSK for %s",id);

	// it is the job of the server to choose the correct PSK for the provided client id, in this example we have
	// only one possible client identity, here is its key
	static const dtls_psk_key_t client_psk = {
		.id = (unsigned char *)"Client_identity",
		.id_length = 15,
		.key = (unsigned char *)"secretPSK",
		.key_length = 9
	};

	// this is out identity, we send this to the client in the DTLS handshake so it knows which key to use for us
	// this doesn't have a key as it is never returned as keying material, only as identifying material
	static const dtls_psk_key_t server_psk = {
		.id = (unsigned char *)"Server_identity",
		.id_length = 15,
		.key = NULL,
		.key_length = 0
	};

	// when id is null, tinydtls wants our identity to use in the handshake
	// this happens when a client connects
	if(id==NULL) {
		// return self identity
		*result = &server_psk;
		return 0;
	}

	// otherwise chose the correct key based on the client's identity
	if(strcmp((char*)id,"Client_identity")==0) {
		*result = &client_psk;
	}

	// TODO, cause handshake to fail if server key identity cannot be found
	// use a hash table to store the identities, or maybe an external entity, perhaps even LDAP
	return 0;
}

// this is called by tinydtls after the DTLS handshake is finished, every
// time it receives application data. tinydtls decrypts the application data and
// passes it here
int tinydtls_read_callback(struct dtls_context_t *ctx, session_t *session, uint8 *data, size_t len) {
	DBG("tinydtls_read_callback");

	// two special strings handle close and re-negotiate
	if(len >= strlen(DTLS_SERVER_CMD_CLOSE) &&
		!memcmp(data, DTLS_SERVER_CMD_CLOSE, strlen(DTLS_SERVER_CMD_CLOSE))) {
		DBG("server: closing connection");
		dtls_close(ctx, session);
		return len;
	} else if (len >= strlen(DTLS_SERVER_CMD_RENEGOTIATE) &&
		!memcmp(data, DTLS_SERVER_CMD_RENEGOTIATE, strlen(DTLS_SERVER_CMD_RENEGOTIATE))) {
		DBG("server: renegotiate connection");
		dtls_renegotiate(ctx, session);
		return len;
	}

	// otherwise the data should be a CoAP PDU
	// try and receive it
	CoapPDU *recvPDU = new CoapPDU(data,len,len);
	if(recvPDU->validate()) {
		INFO("Valid CoAP PDU received");
		recvPDU->printHuman();
	} else {
		INFO("Invalid CoAP PDU received");
	}

	// at present just send an ACK, using the same PDU and space
	recvPDU->reset();
	recvPDU->setVersion(1);
	recvPDU->setType(CoapPDU::COAP_ACKNOWLEDGEMENT);
	dtls_write(ctx, session, data, recvPDU->getPDULength());
	delete recvPDU;
	return 0;
}

// this is called by tinydtls when it wants to send data
// it is our job to actually send the data on its behalf
int tinydtls_send_callback(
	struct dtls_context_t *ctx, 
	session_t *session, 
	uint8 *data, size_t len) {

	INFO("tinydtls_send_called");
	int fd = *(int *)dtls_get_app_data(ctx);
	return sendto(fd, data, len, MSG_DONTWAIT,&session->addr.sa, session->size);
}

// called whenever a significant tinydtls event occurs
// presently only on a successful connect and on a session termination
int tinydtls_event_callback(
	struct dtls_context_t *ctx,
	session_t *session, 
	dtls_alert_level_t level,
	unsigned short code) {

	if(code==0) {
		DBG("DTLS session ended.");
		return 0;
	}
	
	DBG("DTLS session established.");
	return 0;
}

// called by libevent whenever a read occurs on our UDP socket
// it is our job to pass the data to tinydtls for handling
void libevent_recvfrom_callback(evutil_socket_t sockfd, short event, void *arg) {
	// get the base
	char buf[1024];
	char hostStr[128],servStr[128];
	int hostStrLen = 128, servStrLen = 128;

	INFO("Got an event on socket %d:%s%s%s%s",
		(int) sockfd,
		(event&EV_TIMEOUT) ? " timeout" : "",
		(event&EV_READ)    ? " read" : "",
		(event&EV_WRITE)   ? " write" : "",
		(event&EV_SIGNAL)  ? " signal" : ""
	);

	session_t session;
	memset(&session, 0, sizeof(session_t));
	session.size = sizeof(session.addr);

	int bytes = recvfrom(sockfd,(void*)&buf,(size_t)1024,0,&session.addr.sa, &session.size);

	INFO("session address family: %d, size: %d",session.addr.sa.sa_family,session.size);

	//(struct sockaddr *)&fromAddr,&fromAddrLen);
	if(bytes>0) {
		buf[bytes] = 0x00;
		// try to get hostname and service
		if(getnameinfo((struct sockaddr*)&session.addr.sa,session.size,hostStr,hostStrLen,servStr,servStrLen,0)==0) {
			INFO("Received %d bytes from %s:%s",bytes,hostStr,servStr);
		} else {
			INFO("Received %d bytes from %s:%d",bytes,inet_ntoa(session.addr.sin.sin_addr),ntohs(session.addr.sin.sin_port));
		}
		INFO("Got: \"%s\"",buf);
	}

	DBG("calling dtls_handle_message with context: %lx, session: %lx, buf: %lx, bytes: %d",
		(unsigned long)g_dtls_context,(unsigned long)&session,(unsigned long)buf,bytes);
	dtls_handle_message(g_dtls_context, &session, (uint8_t*)buf, bytes);
}

int main(int argc, char **argv) {
	// parse options	
	if(argc!=3) {
		printf("USAGE\n   %s listenAddress listenPort\r\n",argv[0]);
		return 0;
	}

	char *listenAddressString = argv[1];
	char *listenPortString    = argv[2];

	// locals
	evutil_socket_t listener;
	struct addrinfo *bindAddr;
	struct event_base *base = NULL;
	struct event *listener_event = NULL;
   int one = 1;

	// libevent2 requires that you have an event base to which all events are tied
   base = event_base_new();
	if(!base) {
		DBG("Error constructing event base");
		exit(1);
	}

	// get an address structure for the listening port
	int ret = setupAddress(listenAddressString,listenPortString,&bindAddr,SOCK_DGRAM,AF_INET);
	INFO("Setting up bind address");
	if(ret!=0) {
		DBG("Error setting up bind address, exiting. ");
		exit(1);
	}

	// iterate through returned structure to see what we got
	printAddressStructures(bindAddr);

	// setup socket with specified address
	listener = socket(bindAddr->ai_family,bindAddr->ai_socktype,bindAddr->ai_protocol);
   evutil_make_socket_nonblocking(listener);
   setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

	// call bind to "listen" on socket
	DBG("Binding socket.");
	if(bind(listener,bindAddr->ai_addr,bindAddr->ai_addrlen)!=0) {
		DBG("Error binding socket");
		perror(NULL);
		exit(1);
	}

	printAddress(bindAddr);

	// setup a new event, tied to base, watching the file descriptor listener
	// watch for read events, added event watching will persist until manual delete,
	// on those events call libevent_recvfrom_callback with the event base passed as a parameter
	listener_event = event_new(
		base,
		listener,
		EV_READ|EV_PERSIST,
		libevent_recvfrom_callback,
		(void*)base
	);

	if(listener_event==NULL) {
		DBG("Error creating listener event");
		return -1;
	}
	event_add(listener_event, NULL);

	struct timeval timeout;
	timeout.tv_sec = 5;

	// DTLS stuff
	dtls_init();
	dtls_set_log_level(LOG_WARN);
	g_dtls_context = dtls_new_context(&listener);

	// setup callback handlers for DTLS
	static dtls_handler_t cb = {
	  .write = tinydtls_send_callback, 				// called when tinydtls needs to send data
	  .read  = tinydtls_read_callback, 				// called when tinydtls has plaintext data
	  .event = tinydtls_event_callback,				// called when either connection setup or close occurs
	  .get_psk_key = tinydtls_getpsk_callback, 	// called to return the correct PSK for a given peer
	  .get_ecdsa_key = NULL,							// called in the case that an ECDSA key is used to get it
	  .verify_ecdsa_key = NULL							// called to verify an ECDSA key
	};
	dtls_set_handler(g_dtls_context, &cb);

	// start the event loop
	event_base_dispatch(base);
	return 0;
}
