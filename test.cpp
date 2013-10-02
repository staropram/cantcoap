#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include "cantcoap.h"
#include <arpa/inet.h>

#include "CUnit/Basic.h"

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
	CoapPDU *pdu = new CoapPDU();
	pdu->setVersion(1);
	pdu->setType(CoapPDU::COAP_CONFIRMABLE);
	pdu->setCode(CoapPDU::COAP_CHANGED);
	CU_ASSERT_NSTRING_EQUAL(optionInsertionTestA,pdu->getPDUPointer(),pdu->getPDULength());
	pdu->addOption(11,3,(uint8_t*)"\x55\x55\x55");
	CU_ASSERT_NSTRING_EQUAL(optionInsertionTestB,pdu->getPDUPointer(),pdu->getPDULength());
	pdu->addOption(11,3,(uint8_t*)"\xff\xff\xff");
	CU_ASSERT_NSTRING_EQUAL(optionInsertionTestC,pdu->getPDUPointer(),pdu->getPDULength());
	pdu->addOption(7,3,(uint8_t*)"\xf7\xf7\xf7");
	CU_ASSERT_NSTRING_EQUAL(optionInsertionTestD,pdu->getPDUPointer(),pdu->getPDULength());
	pdu->addOption(200,3,(uint8_t*)"\x01\x02\x03");
	CU_ASSERT_NSTRING_EQUAL(optionInsertionTestE,pdu->getPDUPointer(),pdu->getPDULength());
	pdu->addOption(190,3,(uint8_t*)"\x03\x02\x01");
	CU_ASSERT_NSTRING_EQUAL(optionInsertionTestF,pdu->getPDUPointer(),pdu->getPDULength());
	pdu->addOption(300,3,(uint8_t*)"\x01\x02\x03");
	CU_ASSERT_NSTRING_EQUAL(optionInsertionTestG,pdu->getPDUPointer(),pdu->getPDULength());
	pdu->addOption(195,3,(uint8_t*)"\x03\x02\x01");
	CU_ASSERT_NSTRING_EQUAL(optionInsertionTestH,pdu->getPDUPointer(),pdu->getPDULength());
	pdu->addOption(1950,3,(uint8_t*)"\x03\x02\x01");
	CU_ASSERT_NSTRING_EQUAL(optionInsertionTestI,pdu->getPDUPointer(),pdu->getPDULength());
	delete pdu;
}

void testHeaderFirstByteConstruction(void) {
	CoapPDU *pdu = new CoapPDU();
	for(int pduVersion=0; pduVersion<4; pduVersion++) {
		for(int pduTypeIndex=0; pduTypeIndex<4; pduTypeIndex++) {
			for(int tokenLength=0; tokenLength<9; tokenLength++) {
				pdu->setVersion(pduVersion);
				pdu->setType(coapTypeVector[pduTypeIndex]);
				pdu->setTokenLength(tokenLength);
				CU_ASSERT_EQUAL(pdu->getVersion(),pduVersion);
				CU_ASSERT_EQUAL(pdu->getType(),coapTypeVector[pduTypeIndex]);
				CU_ASSERT_EQUAL(pdu->getTokenLength(),tokenLength);
			}
		}
	}
	delete pdu;
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
	CoapPDU *pdu = new CoapPDU();
	pdu->setType(CoapPDU::COAP_CONFIRMABLE);
	pdu->setCode(CoapPDU::COAP_CHANGED);
	pdu->setVersion(2);
	pdu->setToken((uint8_t*)"\3\2\1\0",4);
	CU_ASSERT_NSTRING_EQUAL(tokenInsertionA,pdu->getPDUPointer(),pdu->getPDULength());
	pdu->setToken((uint8_t*)"\4\3\2\1\0",5);
	CU_ASSERT_NSTRING_EQUAL(tokenInsertionB,pdu->getPDUPointer(),pdu->getPDULength());
	pdu->setToken((uint8_t*)"\7\6\5\4\3\2\1",8);
	CU_ASSERT_NSTRING_EQUAL(tokenInsertionC,pdu->getPDUPointer(),pdu->getPDULength());
	pdu->setToken((uint8_t*)"\4\3\2\1\0",5);
	CU_ASSERT_NSTRING_EQUAL(tokenInsertionB,pdu->getPDUPointer(),pdu->getPDULength());
	pdu->setToken((uint8_t*)"\3\2\1\0",4);
	CU_ASSERT_NSTRING_EQUAL(tokenInsertionA,pdu->getPDUPointer(),pdu->getPDULength());
	delete pdu;
}

const char *uriSetStringA = "/this/is/a/test/";

void testURISetting(void) {
	CoapPDU *pdu = new CoapPDU();
	pdu->setType(CoapPDU::COAP_CONFIRMABLE);
	pdu->setCode(CoapPDU::COAP_CHANGED);
	pdu->setVersion(2);
	pdu->setURI((char*)uriSetStringA,strlen(uriSetStringA));
	pdu->printHuman();
	/*
	CoapPDU::CoapOption *options = pdu->getOptions();
	CoapPDU::CoapOption *option;
	for(int i=0; i<pdu->getNumOptions(); i++) {
		option = options[i];
		option->
	}
	*/

	delete pdu;
};

// Method CODEs

void testMethodCodes() {
	CoapPDU *pdu = new CoapPDU();
	pdu->setType(CoapPDU::COAP_CONFIRMABLE);
	pdu->setCode(CoapPDU::COAP_CHANGED);
	pdu->setVersion(2);
	for(int codeIndex=0; codeIndex<COAP_NUM_MESSAGE_CODES; codeIndex++) {
		pdu->setCode(coapCodeVector[codeIndex]);
		CU_ASSERT_EQUAL(pdu->getCode(),coapCodeVector[codeIndex]);
	}
	delete pdu;
}

int main(int argc, char **argv) {
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


   // Run all tests using the CUnit Basic interface
   CU_basic_set_mode(CU_BRM_VERBOSE);
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
