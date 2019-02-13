#pragma once

/// Copyright (c) 2013, Ashley Mills.
#include <unistd.h>
#include <stdint.h>
#include "dbg.h"

#define COAP_HDR_SIZE 4
#define COAP_OPTION_HDR_BYTE 1

// CoAP PDU format

//   0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |Ver| T |  TKL  |      Code     |          Message ID           |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |   Token (if any, TKL bytes) ...
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |   Options (if any) ...
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |1 1 1 1 1 1 1 1|    Payload (if any) ...
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

class CoapPDU {


	public:
		/// CoAP message types. Note, values only work as enum.
		enum Type {
			COAP_CONFIRMABLE=0x00,
			COAP_NON_CONFIRMABLE=0x10,
			COAP_ACKNOWLEDGEMENT=0x20,
			COAP_RESET=0x30
		};

		// CoAP response codes.
		enum Code {
			COAP_EMPTY=0x00,
			COAP_GET,
			COAP_POST,
			COAP_PUT,
			COAP_DELETE,
			COAP_LASTMETHOD=0x1F,
			COAP_CREATED=0x41,
			COAP_DELETED,
			COAP_VALID,
			COAP_CHANGED,
			COAP_CONTENT,
			COAP_BAD_REQUEST=0x80,
			COAP_UNAUTHORIZED,
			COAP_BAD_OPTION,
			COAP_FORBIDDEN,
			COAP_NOT_FOUND,
			COAP_METHOD_NOT_ALLOWED,
			COAP_NOT_ACCEPTABLE,
			COAP_PRECONDITION_FAILED=0x8C,
			COAP_REQUEST_ENTITY_TOO_LARGE=0x8D,
			COAP_UNSUPPORTED_CONTENT_FORMAT=0x8F,
			COAP_INTERNAL_SERVER_ERROR=0xA0,
			COAP_NOT_IMPLEMENTED,
			COAP_BAD_GATEWAY,
			COAP_SERVICE_UNAVAILABLE,
			COAP_GATEWAY_TIMEOUT,
			COAP_PROXYING_NOT_SUPPORTED,
			COAP_UNDEFINED_CODE=0xFF
		};

		/// CoAP option numbers.
		enum Option {
			COAP_OPTION_IF_MATCH=1,
			COAP_OPTION_URI_HOST=3,
			COAP_OPTION_ETAG,
			COAP_OPTION_IF_NONE_MATCH,
			COAP_OPTION_OBSERVE,
			COAP_OPTION_URI_PORT,
			COAP_OPTION_LOCATION_PATH,
			COAP_OPTION_URI_PATH=11,
			COAP_OPTION_CONTENT_FORMAT,
			COAP_OPTION_MAX_AGE=14,
			COAP_OPTION_URI_QUERY,
			COAP_OPTION_ACCEPT=17,
			COAP_OPTION_LOCATION_QUERY=20,
			COAP_OPTION_BLOCK2=23,
			COAP_OPTION_BLOCK1=27,
			COAP_OPTION_SIZE2,
			COAP_OPTION_PROXY_URI=35,
			COAP_OPTION_PROXY_SCHEME=39,
			COAP_OPTION_SIZE1=60
		};

		/// CoAP content-formats.
		enum ContentFormat {
			/* https://www.iana.org/assignments/core-parameters/core-parameters.xhtml#content-formats */
			/* 0-255  Expert Review */
			COAP_CONTENT_FORMAT_TEXT_PLAIN           = 0    ,  //  text/plain; charset=utf-8                    /* Ref: [RFC2046][RFC3676][RFC5147] */
			COAP_CONTENT_FORMAT_APP_COSE_ENCRYPT0    = 16   ,  //  application/cose; cose-type="cose-encrypt0"  /* Ref: [RFC8152] */
			COAP_CONTENT_FORMAT_APP_COSE_MAC0        = 17   ,  //  application/cose; cose-type="cose-mac0"      /* Ref: [RFC8152] */
			COAP_CONTENT_FORMAT_APP_COSE_SIGN1       = 18   ,  //  application/cose; cose-type="cose-sign1"     /* Ref: [RFC8152] */
			COAP_CONTENT_FORMAT_APP_LINKFORMAT       = 40   ,  //  application/link-format                      /* Ref: [RFC6690] */
			COAP_CONTENT_FORMAT_APP_XML              = 41   ,  //  application/xml                              /* Ref: [RFC3023] */
			COAP_CONTENT_FORMAT_APP_OCTECT_STREAM    = 42   ,  //  application/octet-stream                     /* Ref: [RFC2045][RFC2046] */
			COAP_CONTENT_FORMAT_APP_EXI              = 47   ,  //  application/exi                              /* Ref: ["Efficient XML Interchange (EXI) Format 1.0 (Second Edition)" ,February 2014] */
			COAP_CONTENT_FORMAT_APP_JSON             = 50   ,  //  application/json                             /* Ref: [RFC4627] */
			COAP_CONTENT_FORMAT_APP_JSON_PATCH_JSON  = 51   ,  //  application/json-patch+json                  /* Ref: [RFC6902] */
			COAP_CONTENT_FORMAT_APP_MERGE_PATCH_JSON = 52   ,  //  application/merge-patch+json                 /* Ref: [RFC7396] */
			COAP_CONTENT_FORMAT_APP_CBOR             = 60   ,  //  application/cbor                             /* Ref: [RFC7049] */
			COAP_CONTENT_FORMAT_APP_CWT              = 61   ,  //  application/cwt                              /* Ref: [RFC8392] */
			COAP_CONTENT_FORMAT_APP_COSE_ENCRYPT     = 96   ,  //  application/cose; cose-type="cose-encrypt"   /* Ref: [RFC8152] */
			COAP_CONTENT_FORMAT_APP_COSE_MAC         = 97   ,  //  application/cose; cose-type="cose-mac"       /* Ref: [RFC8152] */
			COAP_CONTENT_FORMAT_APP_COSE_SIGN        = 98   ,  //  application/cose; cose-type="cose-sign"      /* Ref: [RFC8152] */
			COAP_CONTENT_FORMAT_APP_COSE_KEY         = 101  ,  //  application/cose-key                         /* Ref: [RFC8152] */
			COAP_CONTENT_FORMAT_APP_COSE_KEY_SET     = 102  ,  //  application/cose-key-set                     /* Ref: [RFC8152] */
			COAP_CONTENT_FORMAT_APP_COAP_GROUP_JSON  = 256  ,  //  application/coap-group+json                  /* Ref: [RFC7390] */
			/* 256-9999  IETF Review or IESG Approval */
			COAP_CONTENT_FORMAT_APP_OMA_TLV_OLD      = 1542 ,  //  Keep old value for backward-compatibility    /* Ref: [OMA-TS-LightweightM2M-V1_0] */
			COAP_CONTENT_FORMAT_APP_OMA_JSON_OLD     = 1543 ,  //  Keep old value for backward-compatibility    /* Ref: [OMA-TS-LightweightM2M-V1_0] */
			/* 10000-64999  First Come First Served */
			COAP_CONTENT_FORMAT_APP_VND_OCF_CBOR     = 10000,  //  application/vnd.ocf+cbor                     /* Ref: [Michael_Koster] */
			COAP_CONTENT_FORMAT_APP_OMA_TLV          = 11542,  //  application/vnd.oma.lwm2m+tlv                /* Ref: [OMA-TS-LightweightM2M-V1_0] */
			COAP_CONTENT_FORMAT_APP_OMA_JSON         = 11543   //  application/vnd.oma.lwm2m+json               /* Ref: [OMA-TS-LightweightM2M-V1_0] */
			/* 65000-65535  Experimental use (no operational use) */
		};

		/// Sequence of these is returned by CoapPDU::getOptions()
		struct CoapOption {
			uint16_t optionDelta;
			uint16_t optionNumber;
			uint16_t optionValueLength;
			int totalLength;
			uint8_t *optionPointer;
			uint8_t *optionValuePointer;
		};

		// construction and destruction
		CoapPDU();
		CoapPDU(uint8_t *pdu, int pduLength);
		CoapPDU(uint8_t *buffer, int bufferLength, int pduLength);
		~CoapPDU();
		int reset();
		int validate();

		// version
		int setVersion(uint8_t version);
		uint8_t getVersion();

		// message type
		void setType(CoapPDU::Type type);
		CoapPDU::Type getType();

		// tokens
		int setTokenLength(uint8_t tokenLength);
		int getTokenLength();
		uint8_t* getTokenPointer();
		int setToken(uint8_t *token, uint8_t tokenLength);

		// message code
		void setCode(CoapPDU::Code code);
		CoapPDU::Code getCode();
		CoapPDU::Code httpStatusToCode(int httpStatus);

		// message ID
		int setMessageID(uint16_t messageID);
		uint16_t getMessageID();

		// options
		int addOption(uint16_t optionNumber, uint16_t optionLength, uint8_t *optionValue);
		// gets a list of all options
		CoapOption* getOptions();
		int getNumOptions();
		// shorthand helpers
		int setURI(char *uri);
		int setURI(char *uri, int urilen);
		int getURI(char *dst, int dstlen, int *outLen);
		int addURIQuery(char *query);

		// content format helper
		int setContentFormat(CoapPDU::ContentFormat format);

		// payload
		uint8_t* mallocPayload(int bytes);
		int setPayload(uint8_t *value, int len);
		uint8_t* getPayloadPointer();
		int getPayloadLength();
		uint8_t* getPayloadCopy();

		// pdu
		int getPDULength();
		uint8_t* getPDUPointer();
		void setPDULength(int len);

		// debugging
		static void printBinary(uint8_t b);
		void print();
		void printBin();
		void printHex();
		void printOptionHuman(uint8_t *option);
		void printHuman();
		void printPDUAsCArray();

	private:
		// variables
		uint8_t *_pdu;
		int _pduLength;

		int _constructedFromBuffer;
		int _bufferLength;

		uint8_t *_payloadPointer;
		int _payloadLength;

		int _numOptions;
		uint16_t _maxAddedOptionNumber;

		// functions
		void shiftPDUUp(int shiftOffset, int shiftAmount);
		void shiftPDUDown(int startLocation, int shiftOffset, int shiftAmount);
		uint8_t codeToValue(CoapPDU::Code c);

		// option stuff
		int findInsertionPosition(uint16_t optionNumber, uint16_t *prevOptionNumber);
		int computeExtraBytes(uint16_t n);
		int insertOption(int insertionPosition, uint16_t optionDelta, uint16_t optionValueLength, uint8_t *optionValue);
		uint16_t getOptionDelta(uint8_t *option);
		void setOptionDelta(int optionPosition, uint16_t optionDelta);
		uint16_t getOptionValueLength(uint8_t *option);

};

/*
#define COAP_CODE_EMPTY 0x00

// method codes 0.01-0.31
#define COAP_CODE_GET 	0x01
#define COAP_CODE_POST 	0x02
#define COAP_CODE_PUT 	0x03
#define COAP_CODE_DELETE 0x04

// Response codes 2.00 - 5.31
// 2.00 - 2.05
#define COAP_CODE_CREATED 0x41
#define COAP_CODE_DELETED 0x42
#define COAP_CODE_VALID   0x43
#define COAP_CODE_CHANGED 0x44
#define COAP_CODE_CONTENT 0x45

// 4.00 - 4.15
#define COAP_CODE_BAD_REQUEST                0x80
#define COAP_CODE_UNAUTHORIZED               0x81
#define COAP_CODE_BAD_OPTION                 0x82
#define COAP_CODE_FORBIDDEN                  0x83
#define COAP_CODE_NOT_FOUND                  0x84
#define COAP_CODE_METHOD_NOT_ALLOWED         0x85
#define COAP_CODE_NOT_ACCEPTABLE             0x86
#define COAP_CODE_PRECONDITION_FAILED        0x8C
#define COAP_CODE_REQUEST_ENTITY_TOO_LARGE   0x8D
#define COAP_CODE_UNSUPPORTED_CONTENT_FORMAT 0x8F

// 5.00 - 5.05
#define COAP_CODE_INTERNAL_SERVER_ERROR      0xA0
#define COAP_CODE_NOT_IMPLEMENTED            0xA1
#define COAP_CODE_BAD_GATEWAY                0xA2
#define COAP_CODE_SERVICE_UNAVAILABLE        0xA3
#define COAP_CODE_GATEWAY_TIMEOUT            0xA4
#define COAP_CODE_PROXYING_NOT_SUPPORTED     0xA5
*/
