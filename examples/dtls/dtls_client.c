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
#define DEFAULT_PORT 20220

static dtls_context_t *dtls_context = NULL;

// TODO add an example that uses this ecdsa stuff
// just ignore all ecdsa references for now
/*
static const unsigned char ecdsa_priv_key[] = {
			0x41, 0xC1, 0xCB, 0x6B, 0x51, 0x24, 0x7A, 0x14,
			0x43, 0x21, 0x43, 0x5B, 0x7A, 0x80, 0xE7, 0x14,
			0x89, 0x6A, 0x33, 0xBB, 0xAD, 0x72, 0x94, 0xCA,
			0x40, 0x14, 0x55, 0xA1, 0x94, 0xA9, 0x49, 0xFA};

static const unsigned char ecdsa_pub_key_x[] = {
			0x36, 0xDF, 0xE2, 0xC6, 0xF9, 0xF2, 0xED, 0x29,
			0xDA, 0x0A, 0x9A, 0x8F, 0x62, 0x68, 0x4E, 0x91,
			0x63, 0x75, 0xBA, 0x10, 0x30, 0x0C, 0x28, 0xC5,
			0xE4, 0x7C, 0xFB, 0xF2, 0x5F, 0xA5, 0x8F, 0x52};

static const unsigned char ecdsa_pub_key_y[] = {
			0x71, 0xA0, 0xD4, 0xFC, 0xDE, 0x1A, 0xB8, 0x78,
			0x5A, 0x3C, 0x78, 0x69, 0x35, 0xA7, 0xCF, 0xAB,
			0xE9, 0x3F, 0x98, 0x72, 0x09, 0xDA, 0xED, 0x0B,
			0x4F, 0xAB, 0xC3, 0x6F, 0xC7, 0x72, 0xF8, 0x29};

int
get_ecdsa_key(struct dtls_context_t *ctx,
			const session_t *session,
	      const dtls_ecdsa_key_t **result) {

  static const dtls_ecdsa_key_t ecdsa_key = {
    .curve = DTLS_ECDH_CURVE_SECP256R1,
    .priv_key = ecdsa_priv_key,
    .pub_key_x = ecdsa_pub_key_x,
    .pub_key_y = ecdsa_pub_key_y
  };

  *result = &ecdsa_key;
  return 0;
}

int
verify_ecdsa_key(struct dtls_context_t *ctx,
		 const session_t *session,
		 const unsigned char *other_pub_x,
		 const unsigned char *other_pub_y,
		 size_t key_size) {
  return 0;
}
*/

// libevent callback
void libevent_recvfrom_callback(evutil_socket_t sockfd, short event, void *arg) {
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

	int bytes = recvfrom(sockfd,(void*)&buf,(size_t)1024,0,
			 &session.addr.sa, &session.size);

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
		(unsigned long)dtls_context,(unsigned long)&session,(unsigned long)buf,bytes);
	dtls_handle_message(dtls_context, &session, (uint8_t*)buf, bytes);
}

///////// DTLS STUFF


/**
 * DTLS key management callback.
 * This function is used to manage the pre-shared keys and identities used to authenticate self to others and others to self.
 * It has two invocations by tinydtls:
 *
 * 1. We are acting as a server, a client has connected to us and we need to send it our ID
 *    In this case tinydtls asks for our identity by setting id to NULL.
 * 2. We are a client connecting to a server, the server has identified itself with an ID
 *    and we need to tell tinydtls which key to use with this peer.
 */
int tinydtls_getpsk_callback(
	struct dtls_context_t *ctx,
	const session_t *session,
	const unsigned char *id,
	size_t id_len,
	const dtls_psk_key_t **result) {

	DBG("Been asked to get PSK for %s",id);

	// this is out identity, we send this to the server in the DTLS handshake so it knows which key to use for us
	static const dtls_psk_key_t client_psk = {
		.id = (unsigned char *)"Client_identity",
		.id_length = 15,
		.key = (unsigned char *)"secretPSK",
		.key_length = 9
	};


	// when id is null, tinydtls wants our identity to use in the handshake
	// this won't happen for the client because nobody should connect to us (maybe return NULL? XXX)
	if(id==NULL) {
		// this is the self identity
		*result = &client_psk;
		return 0;
	}

	// chose the correct key based on the server's identity
	if(strcmp((char*)id,"Server_identity")==0) {
		*result = &client_psk;
	}

	// TODO, cause handshake to fail if server key identity cannot be found
	// use a hash table to store the identities, or maybe an external entity, perhaps even LDAP
	return 0;
}

// this is called by tinydtls after it decrypts received data
int tinydtls_read_callback(struct dtls_context_t *ctx, session_t *session, uint8 *data, size_t len) {
	DBG("tinydtls_read_callback");

	// validate packet
	CoapPDU *recvPDU = new CoapPDU(data,len,len);
	if(recvPDU->validate()!=1) {
		INFO("Malformed CoAP packet");
		return -1;
	}
	INFO("Valid CoAP PDU received");
	recvPDU->printHuman();
	delete recvPDU;

	// extract coap response
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

session_t g_dst;

// called whenever a significant tinydtls event occurs
// presently only on a successful connect and on connection termination
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
	int ret = dtls_write(ctx, &g_dst, pdu->getPDUPointer(), pdu->getPDULength());
	if(ret!=pdu->getPDULength()) {
		INFO("Error sending packet.");
		perror(NULL);
		return -1;
	}
	INFO("Packet sent");
	
	return 0;
}

static dtls_handler_t cb = {
  .write = tinydtls_send_callback,
  .read  = tinydtls_read_callback,
  .event = tinydtls_event_callback,
  .get_psk_key = tinydtls_getpsk_callback,
  .get_ecdsa_key = NULL,
  .verify_ecdsa_key = NULL 
};

#define DTLS_CLIENT_CMD_CLOSE "client:close"
#define DTLS_CLIENT_CMD_RENEGOTIATE "client:renegotiate"

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

	// locals
	evutil_socket_t listener_fd;
	struct addrinfo *bindAddr;
	struct event_base *base = NULL;
	struct event *listener_event = NULL;

	// libevent2 requires that you have an event base to which all events are tied
	base = event_base_new();
	if(!base) {
		DBG("Error constructing event base");
		return -1;
	}

	// setup bind address
	INFO("Setting up bind address");
	int ret = setupAddress(listenAddressString,listenPortString,&bindAddr,SOCK_DGRAM,AF_INET);
	if(ret!=0) {
		INFO("Error setting up bind address, exiting.");
		return -1;
	}

	// iterate through returned structure to see what we got
	printAddressStructures(bindAddr);

	// setup socket
	listener_fd = socket(bindAddr->ai_family,bindAddr->ai_socktype,bindAddr->ai_protocol);
	evutil_make_socket_nonblocking(listener_fd);
	int one = 1;
	setsockopt(listener_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

	// call bind
	DBG("Binding socket.");
	if(bind(listener_fd,bindAddr->ai_addr,bindAddr->ai_addrlen)!=0) {
		DBG("Error binding socket");
		perror(NULL);
		failGracefully(5);
	}
	
	//
	printAddress(bindAddr);

	// construct the remote address
	struct addrinfo *remoteAddress;
	ret = setupAddress(remoteAddressString,remotePortString,&remoteAddress,SOCK_DGRAM,AF_INET);
	if(ret!=0) {
		INFO("Error setting up remote address, exiting.");
		return -1;
	}
	// copy the remote address into a tinydtls session_t struct
	memset(&g_dst, 0, sizeof(session_t));
	g_dst.size = sizeof(sockaddr_in);
	memcpy(&g_dst.addr, remoteAddress->ai_addr, g_dst.size);

	// setup a new event, tied to base, watching the file descriptor listener
	// watch for read events, added event watching will persist until manual delete,
	// on those events call do_accept with the event base passed as a parameter
	listener_event = event_new(
		base,
		listener_fd,
		EV_READ|EV_PERSIST,
		libevent_recvfrom_callback,
		(void*)base
	);

	if(listener_event==NULL) {
		DBG("Error creating listener event");
		return -1;
	}
	event_add(listener_event, NULL);

	// dtls stuff
	dtls_init();
	dtls_set_log_level(LOG_WARN);


	dtls_context = dtls_new_context(&listener_fd);
	if(!dtls_context) {
		dsrv_log(LOG_EMERG, "cannot create context\n");
		exit(-1);
	}

	dtls_set_handler(dtls_context, &cb);

	dtls_connect(dtls_context, &g_dst);

	// start the event loop
	event_base_dispatch(base);
	return 0;
}
