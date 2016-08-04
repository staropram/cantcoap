#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include "cantcoap.h"
#include <arpa/inet.h>

#include "CUnit/Basic.h"

#include "dbg.h"

void testHeaderFirstByteConstruction();
void testMethodCodes();
void testOptionInsertion();
void testTokenInsertion();
void testAgainstServer(CoapPDU *pdu);

// some macros for portability with mbed code

//< Possible CoAP message types
#define COAP_NUM_MESSAGE_TYPES 4
static CoapPDU::Type coapTypeVector[COAP_NUM_MESSAGE_TYPES] = {
	CoapPDU::COAP_CONFIRMABLE,
	CoapPDU::COAP_NON_CONFIRMABLE,
	CoapPDU::COAP_ACKNOWLEDGEMENT,
	CoapPDU::COAP_RESET
};

//< Possible CoAP message codes
#define COAP_NUM_MESSAGE_CODES 26
static CoapPDU::Code coapCodeVector[COAP_NUM_MESSAGE_CODES] = {
	CoapPDU::COAP_EMPTY,
	CoapPDU::COAP_GET,
	CoapPDU::COAP_POST,
	CoapPDU::COAP_PUT,
	CoapPDU::COAP_DELETE,
	CoapPDU::COAP_CREATED,
	CoapPDU::COAP_DELETED,
	CoapPDU::COAP_VALID,
	CoapPDU::COAP_CHANGED,
	CoapPDU::COAP_CONTENT,
	CoapPDU::COAP_BAD_REQUEST,
	CoapPDU::COAP_UNAUTHORIZED,
	CoapPDU::COAP_BAD_OPTION,
	CoapPDU::COAP_FORBIDDEN,
	CoapPDU::COAP_NOT_FOUND,
	CoapPDU::COAP_METHOD_NOT_ALLOWED,
	CoapPDU::COAP_NOT_ACCEPTABLE,
	CoapPDU::COAP_PRECONDITION_FAILED,
	CoapPDU::COAP_REQUEST_ENTITY_TOO_LARGE,
	CoapPDU::COAP_UNSUPPORTED_CONTENT_FORMAT,
	CoapPDU::COAP_INTERNAL_SERVER_ERROR,
	CoapPDU::COAP_NOT_IMPLEMENTED,
	CoapPDU::COAP_BAD_GATEWAY,
	CoapPDU::COAP_SERVICE_UNAVAILABLE,
	CoapPDU::COAP_GATEWAY_TIMEOUT,
	CoapPDU::COAP_PROXYING_NOT_SUPPORTED
};

int one() { return 1; }

// option insertion

const uint8_t optionInsertionTestA[] = {
	0x40, 0x44, 0x00, 0x00
};
const uint8_t optionInsertionTestB[] = {
	0x40, 0x44, 0x00, 0x00, 0xb3, 0x55, 0x55, 0x55
};
const uint8_t optionInsertionTestC[] = {
	0x40, 0x44, 0x00, 0x00, 0xb3, 0x55, 0x55, 0x55, 0x03, 0xff, 0xff, 0xff
};
const uint8_t optionInsertionTestD[] = {
	0x40, 0x44, 0x00, 0x00, 0x73, 0xf7, 0xf7, 0xf7, 0x43, 0x55, 0x55, 0x55, 0x03, 0xff, 0xff, 0xff,
};
const uint8_t optionInsertionTestE[] = {
	0x40, 0x44, 0x00, 0x00, 0x73, 0xf7, 0xf7, 0xf7, 0x43, 0x55, 0x55, 0x55, 0x03, 0xff, 0xff, 0xff, 0xd3, 0xb0, 0x01, 0x02, 0x03,
};
const uint8_t optionInsertionTestF[] = {
	0x40, 0x44, 0x00, 0x00, 0x73, 0xf7, 0xf7, 0xf7, 0x43, 0x55, 0x55, 0x55, 0x03, 0xff, 0xff, 0xff, 0xd3, 0xa6, 0x03, 0x02, 0x01, 0xa3, 0x01, 0x02, 0x03,
};
const uint8_t optionInsertionTestG[] = {
	0x40, 0x44, 0x00, 0x00, 0x73, 0xf7, 0xf7, 0xf7, 0x43, 0x55, 0x55, 0x55, 0x03, 0xff, 0xff, 0xff, 0xd3, 0xa6, 0x03, 0x02, 0x01, 0xa3, 0x01, 0x02, 0x03, 0xd3, 0x57, 0x01, 0x02, 0x03,
};

const uint8_t optionInsertionTestH[] = {
	0x40, 0x44, 0x00, 0x00, 0x73, 0xf7, 0xf7, 0xf7, 0x43, 0x55, 0x55, 0x55, 0x03, 0xff, 0xff, 0xff, 0xd3, 0xa6, 0x03, 0x02, 0x01, 0x53, 0x03, 0x02, 0x01, 0x53, 0x01, 0x02, 0x03, 0xd3, 0x57, 0x01, 0x02, 0x03,
};

const uint8_t optionInsertionTestI[] = {
	0x40, 0x44, 0x00, 0x00, 0x73, 0xf7, 0xf7, 0xf7, 0x43, 0x55, 0x55, 0x55, 0x03, 0xff, 0xff, 0xff, 0xd3, 0xa6, 0x03, 0x02, 0x01, 0x53, 0x03, 0x02, 0x01, 0x53, 0x01, 0x02, 0x03, 0xd3, 0x57, 0x01, 0x02, 0x03, 0xe3, 0x65, 0x05, 0x03, 0x02, 0x01,
};

void testOptionInsertion(void) {
	CoapPDU *pdu = NULL;
	uint8_t *buffer[64];

	for(int constructorType=0; constructorType<4; constructorType++) {
		DBG("New iteration: constructorType: %d",constructorType);
		switch(constructorType) {
			case 0:
				pdu = new CoapPDU((uint8_t*)buffer,64,0);
			break;
			case 1:
				pdu->reset();
			break;
			case 2:
				pdu = new CoapPDU();
			break;
			case 3:
				pdu->reset();
			break;
		}
		pdu->setVersion(1);
		pdu->setType(CoapPDU::COAP_CONFIRMABLE);
		pdu->setCode(CoapPDU::COAP_CHANGED);
		CU_ASSERT_NSTRING_EQUAL_FATAL(optionInsertionTestA,pdu->getPDUPointer(),pdu->getPDULength());
		pdu->addOption(11,3,(uint8_t*)"\x55\x55\x55");
		CU_ASSERT_NSTRING_EQUAL_FATAL(optionInsertionTestB,pdu->getPDUPointer(),pdu->getPDULength());
		pdu->addOption(11,3,(uint8_t*)"\xff\xff\xff");
		CU_ASSERT_NSTRING_EQUAL_FATAL(optionInsertionTestC,pdu->getPDUPointer(),pdu->getPDULength());
		pdu->addOption(7,3,(uint8_t*)"\xf7\xf7\xf7");
		CU_ASSERT_NSTRING_EQUAL_FATAL(optionInsertionTestD,pdu->getPDUPointer(),pdu->getPDULength());
		pdu->addOption(200,3,(uint8_t*)"\x01\x02\x03");
		CU_ASSERT_NSTRING_EQUAL_FATAL(optionInsertionTestE,pdu->getPDUPointer(),pdu->getPDULength());
		pdu->addOption(190,3,(uint8_t*)"\x03\x02\x01");
		CU_ASSERT_NSTRING_EQUAL_FATAL(optionInsertionTestF,pdu->getPDUPointer(),pdu->getPDULength());
		pdu->addOption(300,3,(uint8_t*)"\x01\x02\x03");
		CU_ASSERT_NSTRING_EQUAL_FATAL(optionInsertionTestG,pdu->getPDUPointer(),pdu->getPDULength());
		pdu->addOption(195,3,(uint8_t*)"\x03\x02\x01");
		CU_ASSERT_NSTRING_EQUAL_FATAL(optionInsertionTestH,pdu->getPDUPointer(),pdu->getPDULength());
		pdu->addOption(1950,3,(uint8_t*)"\x03\x02\x01");
		CU_ASSERT_NSTRING_EQUAL_FATAL(optionInsertionTestI,pdu->getPDUPointer(),pdu->getPDULength());
		if(constructorType%2) {
			DBG("%d DELETE",constructorType);
			delete pdu;
		}
	}
}

void testHeaderFirstByteConstruction(void) {
	CoapPDU *pdu = NULL;
	uint8_t *buffer[64];

	for(int constructorType=0; constructorType<4; constructorType++) {
		DBG("New iteration: constructorType: %d",constructorType);
		switch(constructorType) {
			case 0:
				pdu = new CoapPDU((uint8_t*)buffer,64,0);
			break;
			case 1:
				pdu->reset();
			break;
			case 2:
				pdu = new CoapPDU();
			break;
			case 3:
				pdu->reset();
			break;
		}
		for(int pduVersion=0; pduVersion<4; pduVersion++) {
			for(int pduTypeIndex=0; pduTypeIndex<4; pduTypeIndex++) {
				for(int tokenLength=0; tokenLength<9; tokenLength++) {
					pdu->setVersion(pduVersion);
					pdu->setType(coapTypeVector[pduTypeIndex]);
					pdu->setTokenLength(tokenLength);
					CU_ASSERT_EQUAL_FATAL(pdu->getVersion(),pduVersion);
					CU_ASSERT_EQUAL_FATAL(pdu->getType(),coapTypeVector[pduTypeIndex]);
					CU_ASSERT_EQUAL_FATAL(pdu->getTokenLength(),tokenLength);
				}
			}
		}
		if(constructorType%2) {
			DBG("%d DELETE",constructorType);
			delete pdu;
		}
	}
}

// TOKEN insertion

const uint8_t tokenInsertionA[] = {
	0x84, 0x44, 0x00, 0x00, 0x03, 0x02, 0x01, 0x00,
};
const uint8_t tokenInsertionB[] = {
	0x85, 0x44, 0x00, 0x00, 0x04, 0x03, 0x02, 0x01, 0x00,
};
const uint8_t tokenInsertionC[] = {
	0x88, 0x44, 0x00, 0x00, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00,
};

void testTokenInsertion(void) {
	CoapPDU *pdu = NULL;
	uint8_t *buffer[64];

	for(int constructorType=0; constructorType<4; constructorType++) {
		DBG("New iteration: constructorType: %d",constructorType);
		switch(constructorType) {
			case 0:
				pdu = new CoapPDU((uint8_t*)buffer,64,0);
			break;
			case 1:
				pdu->reset();
			break;
			case 2:
				pdu = new CoapPDU();
			break;
			case 3:
				pdu->reset();
			break;
		}
		pdu->setType(CoapPDU::COAP_CONFIRMABLE);
		pdu->setCode(CoapPDU::COAP_CHANGED);
		pdu->setVersion(2);
		pdu->setToken((uint8_t*)"\3\2\1\0",4);
		CU_ASSERT_NSTRING_EQUAL_FATAL(tokenInsertionA,pdu->getPDUPointer(),pdu->getPDULength());
		pdu->setToken((uint8_t*)"\4\3\2\1\0",5);
		CU_ASSERT_NSTRING_EQUAL_FATAL(tokenInsertionB,pdu->getPDUPointer(),pdu->getPDULength());
		pdu->setToken((uint8_t*)"\7\6\5\4\3\2\1",8);
		CU_ASSERT_NSTRING_EQUAL_FATAL(tokenInsertionC,pdu->getPDUPointer(),pdu->getPDULength());
		pdu->setToken((uint8_t*)"\4\3\2\1\0",5);
		CU_ASSERT_NSTRING_EQUAL_FATAL(tokenInsertionB,pdu->getPDUPointer(),pdu->getPDULength());
		pdu->setToken((uint8_t*)"\3\2\1\0",4);
		CU_ASSERT_NSTRING_EQUAL_FATAL(tokenInsertionA,pdu->getPDUPointer(),pdu->getPDULength());
		CU_ASSERT_FATAL(pdu->setToken(NULL,4)==1);
		CU_ASSERT_FATAL(pdu->setToken((uint8_t*)"a",0)==1);
		if(constructorType%2) {
			DBG("%d DELETE",constructorType);
			delete pdu;
		}
	}
}

const char *uriInA = "/this/is/a/test";
const char *uriInB = "/this/is/a/test/";
const char *uriInC = "/";
const char *uriInD = "/a/b/c/d/e/f/g/h";
const char *uriInE = "/anothertest";
const char *uriInF = "test";
const char *uriOutF = "/test";
const char *uriInG = "/a/b/c/d?x=1&y=2&z=3";
const char *uriInH = "/a?x=1";
const char *uriInI = "a?x=1";

const char *uriInStrings[9] = {
	uriInA,
	uriInB,
	uriInC,
	uriInD,
	uriInE,
	uriInF,
	uriInG,
	uriInH,
	uriInI,
};

const char *uriOutStrings[9] = {
	uriInA,
	uriInA, // deliberate
	uriInC,
	uriInD,
	uriInE,
	uriOutF,
	uriInG,
	uriInH,
	uriInH,
};

const int numURISetStrings = 9;

void testURISetting(void) {
	// locals
	int bufLen = 64, inLen = 0, outLen = 0, expectedLen = 0;
	char outBuf[64];
	CoapPDU *pdu = NULL;
	char *inBuf = NULL, *expectedBuf = NULL;

	uint8_t *buffer[64];


	// iterate over URIs
	for(int i=0; i<numURISetStrings; i++) {
		inBuf = (char*)uriInStrings[i];
		inLen = strlen(inBuf);
		expectedBuf = (char*)uriOutStrings[i];
		expectedLen = strlen(expectedBuf);

		// construct PDU
		//pdu = new CoapPDU();
		for(int constructorType=0; constructorType<4; constructorType++) {
			DBG("New iteration: constructorType: %d",constructorType);
			switch(constructorType) {
				case 0:
					pdu = new CoapPDU((uint8_t*)buffer,64,0);
				break;
				case 1:
					pdu->reset();
				break;
				case 2:
					pdu = new CoapPDU();
				break;
				case 3:
					pdu->reset();
				break;
			}

			pdu->setType(CoapPDU::COAP_CONFIRMABLE);
			pdu->setCode(CoapPDU::COAP_CHANGED);
			pdu->setVersion(1);
			pdu->setMessageID(rand()%0xFFFF);

			// set URI-PATH options in one operation from URI
			pdu->setURI(inBuf,inLen);
			//pdu->printHuman();

			// check that read URI is the same
			pdu->getURI(outBuf,bufLen,&outLen);

			DBG("Got \"%s\" with length %d, supposed to get: \"%s\" with length %d",outBuf,outLen,expectedBuf,expectedLen);

			CU_ASSERT_EQUAL_FATAL(expectedLen,outLen);
			CU_ASSERT_NSTRING_EQUAL_FATAL(expectedBuf,outBuf,expectedLen);
			//delete pdu;
			if(constructorType%2) {
				DBG("%d DELETE",constructorType);
				delete pdu;
			}
		}
	}

	// test failure cases
	pdu = new CoapPDU();
	pdu->setMessageID(rand()%0xFFFF);
	CU_ASSERT_FATAL(pdu->setURI(NULL,3)==1);
	CU_ASSERT_FATAL(pdu->setURI((char*)"hello",5)==0);
	CU_ASSERT_FATAL(pdu->getURI(NULL,3,NULL)==1);
	CU_ASSERT_FATAL(pdu->getURI(outBuf,20,NULL)==1);
	CU_ASSERT_FATAL(pdu->getURI(outBuf,0,&outLen)==1);
	CU_ASSERT_FATAL(pdu->getURI(outBuf,2,&outLen)==1);
	CU_ASSERT_FATAL(pdu->getURI(outBuf,3,&outLen)==1);
	CU_ASSERT_FATAL(pdu->getURI(outBuf,7,&outLen)==1);
	CU_ASSERT_FATAL(pdu->getURI(outBuf,8,&outLen)==0);
	CU_ASSERT_NSTRING_EQUAL_FATAL(outBuf,"/hello",5);
	delete pdu;
	// case where there is no URI
	pdu = new CoapPDU();
	CU_ASSERT_FATAL(pdu->getURI(outBuf,8,&outLen)==0);
	CU_ASSERT_EQUAL_FATAL(outLen,0);
	delete pdu;

};

// Method CODEs

void testMethodCodes() {
	CoapPDU *pdu = NULL;
	uint8_t *buffer[4];
	for(int i=0; i<4; i++) {
		switch(i) {
			case 0:
				pdu = new CoapPDU((uint8_t*)buffer,4,0);
			break;
			case 1:
				pdu->reset();
			break;
			case 2:
				pdu = new CoapPDU();
			break;
			case 3:
				pdu->reset();
			break;
		}

		pdu->setType(CoapPDU::COAP_CONFIRMABLE);
		pdu->setCode(CoapPDU::COAP_CHANGED);
		pdu->setVersion(1);
		pdu->setMessageID(rand()%0xFFFF);
		for(int codeIndex=0; codeIndex<COAP_NUM_MESSAGE_CODES; codeIndex++) {
			pdu->setCode(coapCodeVector[codeIndex]);
			CU_ASSERT_EQUAL_FATAL(pdu->getCode(),coapCodeVector[codeIndex]);
		}

		if(i%2) {
			DBG("%d DELETE",i);
			delete pdu;
		}
	}
}

// message ID

void testMessageID() {
	CoapPDU *pdu = NULL;
	uint8_t *buffer[4];
	for(int i=0; i<4; i++) {
		switch(i) {
			case 0:
				pdu = new CoapPDU((uint8_t*)buffer,4,0);
			break;
			case 1:
				pdu->reset();
			break;
			case 2:
				pdu = new CoapPDU();
			break;
			case 3:
				pdu->reset();
			break;
		}

		uint16_t messageID = 0, readID = 0;
		pdu->setMessageID(0x0000);
		CU_ASSERT_EQUAL_FATAL(pdu->getMessageID(),0x0000);
		pdu->setMessageID(0x0001);
		CU_ASSERT_EQUAL_FATAL(pdu->getMessageID(),0x0001);
		pdu->setMessageID(0xFFFF);
		CU_ASSERT_EQUAL_FATAL(pdu->getMessageID(),0xFFFF);
		for(int j=0; j<100; j++) {
			messageID = rand()%0xFFFF;
			pdu->setMessageID(messageID);
			readID = pdu->getMessageID();
			CU_ASSERT_EQUAL_FATAL(messageID,readID);
		}

		if(i%2) {
			DBG("%d DELETE",i);
			delete pdu;
		}
	}
}

// payloads
const uint8_t payloadTestPDUA[] = {
   0x40, 0x01, 0x12, 0x34, 0xb4, 0x74, 0x65, 0x73, 0x74, 0xff, 0x01, 0x02, 0x03,
};
const uint8_t payloadTestPDUB[] = {
   0x40, 0x01, 0x12, 0x34, 0xb4, 0x74, 0x65, 0x73, 0x74, 0xff, 0x04, 0x03, 0x02, 0x01
};
const uint8_t payloadTestPDUC[] = {
   0x40, 0x01, 0x12, 0x34, 0xb4, 0x74, 0x65, 0x73, 0x74, 0xff, 0x01, 0x02,
};

void testPayload() {
	// test for both buffer and dynamic
	CoapPDU *pdu = NULL;
	uint8_t *buffer[32];
	for(int i=0; i<4; i++) {
		switch(i) {
			case 0:
				pdu = new CoapPDU((uint8_t*)buffer,32,0);
			break;
			case 1:
				pdu->reset();
			break;
			case 2:
				pdu = new CoapPDU();
			break;
			case 3:
				pdu->reset();
			break;
		}
		pdu->setType(CoapPDU::COAP_CONFIRMABLE);
		#ifdef DEBUG
		pdu->printBin();
		#endif
		pdu->setCode(CoapPDU::COAP_GET);
		pdu->setVersion(1);
		#ifdef DEBUG
		pdu->printBin();
		#endif
		pdu->setMessageID(0x1234);
		pdu->setURI((char*)"test",4);
		#ifdef DEBUG
		pdu->printBin();
		#endif
		CU_ASSERT_FATAL(pdu->setPayload(NULL,4)==1);
		CU_ASSERT_FATAL(pdu->setPayload((uint8_t*)"test",0)==1);
		pdu->setPayload((uint8_t*)"\1\2\3",3);
		#ifdef DEBUG
		pdu->printBin();
		#endif
		CU_ASSERT_EQUAL_FATAL(pdu->getPayloadLength(),3);
		CU_ASSERT_NSTRING_EQUAL_FATAL(pdu->getPDUPointer(),payloadTestPDUA,pdu->getPDULength());
		CU_ASSERT_NSTRING_EQUAL_FATAL(pdu->getPayloadPointer(),"\1\2\3",pdu->getPayloadLength());
		DBG("Trying to increase payload size");
		pdu->setPayload((uint8_t*)"\4\3\2\1",4);
		#ifdef DEBUG
		pdu->printBin();
		#endif
		CU_ASSERT_EQUAL_FATAL(pdu->getPayloadLength(),4);
		CU_ASSERT_NSTRING_EQUAL_FATAL(pdu->getPDUPointer(),payloadTestPDUB,pdu->getPDULength());
		CU_ASSERT_NSTRING_EQUAL_FATAL(pdu->getPayloadPointer(),"\4\3\2\1",pdu->getPayloadLength());
		DBG("Trying to reduce payload size");
		pdu->setPayload((uint8_t*)"\1\2",2);
		#ifdef DEBUG
		pdu->printBin();
		#endif
		CU_ASSERT_EQUAL_FATAL(pdu->getPayloadLength(),2);
		CU_ASSERT_NSTRING_EQUAL_FATAL(pdu->getPDUPointer(),payloadTestPDUC,pdu->getPDULength());
		CU_ASSERT_NSTRING_EQUAL_FATAL(pdu->getPayloadPointer(),"\1\2",pdu->getPayloadLength());
		if(i%2) {
			DBG("%d DELETE",i);
			delete pdu;
		}
	}
}
void testURISizes()
{
    char bigURI[] = "/13456789012345678999999999999999999999999999999999/999999999999999999999999"
        "/22222222222222222222/2222222222222222222222222222222333333333333333333333333333333333/"
        "/22222222222222222222/2222222222222222222222222222222333333333333333333333333333333333/"
        "/22222222222222222222/2222222222222222222222222222222333333333333333333333333333333333/"
        "/22222222222222222222/2222222222222222222222222222222333333333333333333333333333333333/"
        "/22222222222222222222/2222222222222222222222222222222333333333333333333333333333333333/"
        "/22222222222222222222/2222222222222222222222222222222333333333333333333333333333333333/"
        "/22222222222222222222/2222222222222222222222222222222333333333333333333333333333333333/"
        "/22222222222222222222/2222222222222222222222222222222333333333333333333333333333333333/"
        "/22222222222222222222/2222222222222222222222222222222333333333333333333333333333333333/"
        "/22222222222222222222222222222222222222222222222222222222111111111111111111111111111";
    int bigURISize = strlen(bigURI);
    const int bigBufferSize = 1000;
    char bigBuffer[bigBufferSize] = {0};
    int outLen;

    CoapPDU *pdu = new CoapPDU();

    CU_ASSERT_FATAL(pdu->setURI(bigURI, bigURISize)==0);
    pdu->getURI(bigBuffer, bigBufferSize, &outLen);
    CU_ASSERT_NSTRING_EQUAL_FATAL(bigBuffer, bigURI, bigURISize);
    CU_ASSERT_EQUAL_FATAL(bigURISize, outLen);

    const char* littleURI = "/";
    int littleURISize = strlen(littleURI);
    const int littleBufferSize = 10;
    char littleBuffer[littleBufferSize] = {0};
    outLen = 0;

    pdu->reset();

    CU_ASSERT_FATAL(pdu->setURI((char*)littleURI, littleURISize)==0);
    pdu->getURI(littleBuffer, littleBufferSize, &outLen);
    CU_ASSERT_NSTRING_EQUAL_FATAL(littleBuffer, littleURI, littleURISize);
    CU_ASSERT_EQUAL_FATAL(littleURISize, outLen);

    delete pdu;
}

int main(int argc, char **argv) {
	(void)argc;
	(void)argv;
	// use CUnit test framework
	CU_pSuite pSuite = NULL;

	// initialize the CUnit test registry
   if (CUE_SUCCESS != CU_initialize_registry())
      return CU_get_error();

	// add a suite to the registry
   pSuite = CU_add_suite("Header", NULL, NULL);
   if(!pSuite) {
      CU_cleanup_registry();
      return CU_get_error();
   }

	// add the tests to the suite
   if(!CU_add_test(pSuite, "First header byte construction", testHeaderFirstByteConstruction)) {
      CU_cleanup_registry();
      return CU_get_error();
	}

   if(!CU_add_test(pSuite, "Method codes", testMethodCodes)) {
      CU_cleanup_registry();
      return CU_get_error();
   }

   if(!CU_add_test(pSuite, "Message ID", testMessageID)) {
      CU_cleanup_registry();
      return CU_get_error();
   }

   if(!CU_add_test(pSuite, "Token insertion", testTokenInsertion)) {
      CU_cleanup_registry();
      return CU_get_error();
   }

   if(!CU_add_test(pSuite, "Option insertion", testOptionInsertion)) {
      CU_cleanup_registry();
      return CU_get_error();
   }

   if(!CU_add_test(pSuite, "URI setting", testURISetting)) {
      CU_cleanup_registry();
      return CU_get_error();
   }

   if(!CU_add_test(pSuite, "URI sizes", testURISizes)) {
      CU_cleanup_registry();
      return CU_get_error();
   }

	CU_pTest payloadTest = CU_add_test(pSuite, "Payload setting", testPayload);
   if(!payloadTest) {
      CU_cleanup_registry();
      return CU_get_error();
   }

   // Run all tests using the CUnit Basic interface
   CU_basic_set_mode(CU_BRM_VERBOSE);
	CU_set_error_action(CUEA_ABORT);
   CU_basic_run_tests();
   CU_cleanup_registry();
	//optionInsertionTest();
   return CU_get_error();
}


void testAgainstServer(CoapPDU *pdu) {
	pdu->setVersion(1);
	pdu->setType(CoapPDU::COAP_CONFIRMABLE);
	pdu->setCode(CoapPDU::COAP_GET);
	pdu->setToken((uint8_t*)"\3\2\1\0",4);
	pdu->addOption(11,5,(uint8_t*)"hello");
	pdu->addOption(11,5,(uint8_t*)"there");
	pdu->addOption(11,6,(uint8_t*)"server");
	pdu->print();
}
