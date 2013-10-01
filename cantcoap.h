// version, 2 bits
// type, 2 bits
	// 00 Confirmable
	// 01 Non-confirmable
	// 10 Acknowledgement
	// 11 Reset


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
#define COAP_CODE_BAD_REQUEST						0x80
#define COAP_CODE_UNAUTHORIZED					0x81
#define COAP_CODE_BAD_OPTION						0x82
#define COAP_CODE_FORBIDDEN						0x83
#define COAP_CODE_NOT_FOUND    					0x84
#define COAP_CODE_METHOD_NOT_ALLOWED 			0x85
#define COAP_CODE_NOT_ACCEPTABLE					0x86
#define COAP_CODE_PRECONDITION_FAILED			0x8C
#define COAP_CODE_REQUEST_ENTITY_TOO_LARGE	0x8D
#define COAP_CODE_UNSUPPORTED_CONTENT_FORMAT	0x8F

// 5.00 - 5.05
#define COAP_CODE_INTERNAL_SERVER_ERROR		0xA0
#define COAP_CODE_NOT_IMPLEMENTED				0xA1
#define COAP_CODE_BAD_GATEWAY						0xA2
#define COAP_CODE_SERVICE_UNAVAILABLE			0xA3
#define COAP_CODE_GATEWAY_TIMEOUT				0xA4
#define COAP_CODE_PROXYING_NOT_SUPPORTED		0xA5
*/

//#define COAP_CODE.

#define INFO(...) printf(__VA_ARGS__); printf("\r\n");
#define ERR(...) printf(__VA_ARGS__); printf("\r\n");

#ifdef DEBUG
	#define DBG(...) fprintf(stderr,"%s:%d ",__FILE__,__LINE__); fprintf(stderr,__VA_ARGS__); fprintf(stderr,"\r\n");
	#define DBGX(...) fprintf(stderr,__VA_ARGS__);
	#define DBGLX(...) fprintf(stderr,"%s:%d ",__FILE__,__LINE__); fprintf(stderr,__VA_ARGS__);
#else
	#define DBG(...) {};
	#define DBGX(...) {};
	#define DBGLX(...) {};
#endif

#define COAP_HDR_SIZE 4
#define COAP_OPTION_HDR_BYTE 1

// token length, 4 bits
// length of token in bytes (only 0 to 8 bytes allowed)
class CoapPDU {


	public:
		enum Type {
			COAP_CONFIRMABLE=0x00,
			COAP_NON_CONFIRMABLE=0x10,
			COAP_ACKNOWLEDGEMENT=0x20,
			COAP_RESET=0x30
		};

		enum Code {
			COAP_EMPTY=0x00,
			COAP_GET,
			COAP_POST,
			COAP_PUT,
			COAP_DELETE,
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
			COAP_PROXYING_NOT_SUPPORTED
		};

		enum Option {
			COAP_OPTION_IF_MATCH=1,
			COAP_OPTION_URI_HOST=3,
			COAP_OPTION_ETAG,
			COAP_OPTION_IF_NONE_MATCH,
			COAP_OPTION_URI_PORT=7,
			COAP_OPTION_LOCATION_PATH,
			COAP_OPTION_URI_PATH=11,
			COAP_OPTION_CONTENT_FORMAT,
			COAP_OPTION_MAX_AGE=14,
			COAP_OPTION_URI_QUERY,
			COAP_OPTION_ACCEPT=17,
			COAP_OPTION_LOCATION_QUERY=20,
			COAP_OPTION_PROXY_URI=35,
			COAP_OPTION_PROXY_SCHEME=39
		};

		// this is only used externally
		struct CoapOption {
			uint16_t optionDelta;
			uint16_t optionNumber;
			uint16_t optionValueLength;
			int totalLength;
			uint8_t *optionPointer;
			uint8_t *optionValuePointer;
		};

		// constructor and destructor
		CoapPDU();
		CoapPDU(uint8_t *pdu, int pduLength);
		~CoapPDU();

		int isValid();

		// version
		int setVersion(uint8_t version);
		uint8_t getVersion();

		// message type
		void setType(CoapPDU::Type type);
		CoapPDU::Type getType();

		// tokens
		int setTokenLength(uint8_t tokenLength);
		int getTokenLength();
		int setToken(uint8_t *token, uint8_t tokenLength);

		// message code
		void setCode(CoapPDU::Code code);
		CoapPDU::Code getCode();

		// message ID
		int setMessageID(uint16_t messageID);
		uint16_t getMessageID();

		// options
		int addOption(uint16_t optionNumber, uint16_t optionLength, uint8_t *optionValue);
		// gets a list of all options
		CoapOption* getOptions();
		int getNumOptions();

		// debugging
		static void printBinary(uint8_t b);
		void print();
		void printBin();
		void printHex();
		void printOptionHuman(uint8_t *option);
		void printHuman();
		void printPDUAsCArray();

		int getPDULength();
		uint8_t* getPDU();

	public:
		uint8_t *_pdu;
		int _pduLength;

		uint8_t codeToValue(CoapPDU::Code c);

		void shiftPDUUp(int shiftOffset, int shiftAmount);
		void shiftPDUDown(int startLocation, int shiftOffset, int shiftAmount);

		// option stuff
		int findInsertionPosition(uint16_t optionNumber, uint16_t *prevOptionNumber);
		int computeExtraBytes(uint16_t n);
		int insertOption(int insertionPosition, uint16_t optionDelta, uint16_t optionValueLength, uint8_t *optionValue);
		uint16_t getOptionDelta(uint8_t *option);
		void setOptionDelta(int optionPosition, uint16_t optionDelta);
		uint16_t getOptionValueLength(uint8_t *option);
		
		// meta data
		int _numOptions;
		int _optionStart;
		uint16_t _maxAddedOptionNumber;
};
