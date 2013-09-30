/*
Copyright (c) 2013, Ashley Mills.
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met: 

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer. 
2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution. 

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

// version, 2 bits
// type, 2 bits
	// 00 Confirmable
	// 01 Non-confirmable
	// 10 Acknowledgement
	// 11 Reset

//#define DEBUG 1

// token length, 4 bits
// length of token in bytes (only 0 to 8 bytes allowed)
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include "cantcoap.h"
#include "arpa/inet.h"

#define COAP_HDR_SIZE 4
#define COAP_OPTION_HDR_BYTE 1

#ifdef DEBUG
	#define INFO(...) printf(__VA_ARGS__); printf("\r\n")
	#define DBG(...) fprintf(stderr,__VA_ARGS__); fprintf(stderr,"\r\n")
	#define DBGX(...) fprintf(stderr,__VA_ARGS__);
#else
	#define INFO(...) {};
	#define DBG(...) {};
	#define DBGX(...) {};
#endif

/// Constructor
CoapPDU::CoapPDU() {
	_pdu = (uint8_t*)calloc(4,sizeof(uint8_t));
	_pduLength = 4;
	_numOptions = 0;

	// options
	// XXX it would have been nice to use something like UDP_CORK or MSG_MORE 
	// but these aren't implemented for UDP in LwIP. So another option would 
	// be to re-arrange memory every time an option is added out-of-order
	// this would be a ballache however, so for now, we'll just dump this to
	// a PDU at the end
}

CoapPDU::~CoapPDU() {
	free(_pdu);
}

uint8_t* CoapPDU::getPDU() {
	return _pdu;
}


/**
 * Sets the CoAP version.
 * @version CoAP version between 0 and 3.
 */
int CoapPDU::setVersion(uint8_t version) {
	if(version>3) {
		return 0;
	}

	_pdu[0] &= 0x3F;
	_pdu[0] |= (version << 6);
	return 1;
}
		
/**
 * Gets the CoAP Version.
 * @return The CoAP version between 0 and 3.
 */
uint8_t CoapPDU::getVersion() {
	return (_pdu[0]&0xC0)>>6;
}


/**
 * Sets the type of this coap PDU. 
 * @mt The type, one of: COAP_CONFIRMABLE, COAP_NON_CONFIRMABLE, COAP_ACKNOWLEDGEMENT, COAP_RESET.
 */
void CoapPDU::setType(CoapPDU::Type mt) {
	_pdu[0] &= 0xCF;
	_pdu[0] |= mt;
}

CoapPDU::Type CoapPDU::getType() {
	return (CoapPDU::Type)(_pdu[0]&0x30);
}


int CoapPDU::setTokenLength(uint8_t tokenLength) {
	if(tokenLength>8)
		return 1;

	_pdu[0] &= 0xF0;
	_pdu[0] |= tokenLength;
	return 0;
}

int CoapPDU::getTokenLength() {
	return _pdu[0] & 0x0F;
}

int CoapPDU::setToken(uint8_t *token, uint8_t tokenLength) {
	DBG("Setting token");

	// if tokenLength has not changed, just copy the new value
	uint8_t oldTokenLength = getTokenLength();
	if(tokenLength==oldTokenLength) {
		memcpy((void*)&_pdu[4],token,tokenLength);
		return 0;
	}

	// otherwise compute new length of PDU
	uint8_t oldPDULength = _pduLength;
	_pduLength -= oldTokenLength;
	_pduLength += tokenLength;

	// now, have to shift old memory around, but shift direction depends
	// whether pdu is now bigger or smaller
	if(_pduLength>oldPDULength) {
		// new PDU is bigger, need to allocate space for new PDU
		uint8_t *newMemory = (uint8_t*)realloc(_pdu,_pduLength);
		if(newMemory==NULL) {
			// malloc failed
			return 1;
		}
		_pdu = newMemory;

		// and then shift everything after token up to end of new PDU
		// memory overlaps so do this manually so to avoid additional mallocs
		int shiftOffset = _pduLength-oldPDULength;
		int shiftAmount = _pduLength-tokenLength-COAP_HDR_SIZE; // everything after token
		shiftPDUUp(shiftOffset,shiftAmount);

		// now copy the token into the new space and set official token length
		memcpy((void*)&_pdu[4],token,tokenLength);
		setTokenLength(tokenLength);

		// and return success
		return 0;
	}

	// new PDU is smaller, copy the new token value over the old one
	memcpy((void*)&_pdu[4],token,tokenLength);
	// and shift everything after the new token down
	int startLocation = COAP_HDR_SIZE+tokenLength;
	int shiftOffset = oldPDULength-_pduLength;
	int shiftAmount = oldPDULength-oldTokenLength-COAP_HDR_SIZE;
	shiftPDUDown(startLocation,shiftOffset,shiftAmount);
	// then reduce size of buffer
	uint8_t *newMemory = (uint8_t*)realloc(_pdu,_pduLength);
	if(newMemory==NULL) {
		// malloc failed, PDU in inconsistent state
		return 1;
	}
	_pdu = newMemory;
	// and officially set the new tokenLength
	setTokenLength(tokenLength);
	return 0;
}

// this shifts bytes up to the top of the PDU to create space
// the destination always begins at the end of allocated memory
void CoapPDU::shiftPDUUp(int shiftOffset, int shiftAmount) {
	DBG("shiftOffset: %d, shiftAmount: %d",shiftOffset,shiftAmount);
	int destPointer = _pduLength-1;
	int srcPointer  = destPointer-shiftOffset;
	while(shiftAmount--) {
		_pdu[destPointer] = _pdu[srcPointer];
		destPointer--;
		srcPointer--;
	}
}

// shift bytes from 
void CoapPDU::shiftPDUDown(int startLocation, int shiftOffset, int shiftAmount) {
	DBG("startLocation: %d, shiftOffset: %d, shiftAmount: %d",startLocation,shiftOffset,shiftAmount);
	int srcPointer = startLocation+shiftOffset;
	while(shiftAmount--) {
		_pdu[startLocation] = _pdu[srcPointer];
		startLocation++;
		srcPointer++;
	}
}

void CoapPDU::setCode(CoapPDU::Code code) {
	_pdu[1] = code;
	// there is a limited set of response codes
}

CoapPDU::Code CoapPDU::getCode() {
	return (CoapPDU::Code)_pdu[1];
}

/*
		int setMessageID(uint16_t messageID);
		uint16_t getMessageID();
};
*/

void CoapPDU::printHuman() {
	DBG("CoAP Version: %d",getVersion());
	DBGX("Message Type: ");
	switch(getType()) {
		case COAP_CONFIRMABLE:
			DBG("Confirmable");
		break;

		case COAP_NON_CONFIRMABLE:
			DBG("Non-Confirmable");
		break;

		case COAP_ACKNOWLEDGEMENT:
			DBG("Acknowledgement");
		break;

		case COAP_RESET:
			DBG("Reset");
		break;
	}
	DBG("Token length: %d",getTokenLength());
	DBGX("Code: ");
	switch(getCode()) {
		case COAP_EMPTY:
			DBG("0.00 Empty");
		break;
		case COAP_GET:
			DBG("0.01 GET");
		break;
		case COAP_POST:
			DBG("0.02 POST");
		break;
		case COAP_PUT:
			DBG("0.03 PUT");
		break;
		case COAP_DELETE:
			DBG("0.04 DELETE");
		break;
		case COAP_CREATED:
			DBG("2.01 Created");
		break;
		case COAP_DELETED:
			DBG("2.02 Deleted");
		break;
		case COAP_VALID:
			DBG("2.03 Valid");
		break;
		case COAP_CHANGED:
			DBG("2.04 Changed");
		break;
		case COAP_CONTENT:
			DBG("2.05 Content");
		break;
		case COAP_BAD_REQUEST:
			DBG("4.00 Bad Request");
		break;
		case COAP_UNAUTHORIZED:
			DBG("4.01 Unauthorized");
		break;
		case COAP_BAD_OPTION:
			DBG("4.02 Bad Option");
		break;
		case COAP_FORBIDDEN:
			DBG("4.03 Forbidden");
		break;
		case COAP_NOT_FOUND:
			DBG("4.04 Not Found");
		break;
		case COAP_METHOD_NOT_ALLOWED:
			DBG("4.05 Method Not Allowed");
		break;
		case COAP_NOT_ACCEPTABLE:
			DBG("4.06 Not Acceptable");
		break;
		case COAP_PRECONDITION_FAILED:
			DBG("4.12 Precondition Failed");
		break;
		case COAP_REQUEST_ENTITY_TOO_LARGE:
			DBG("4.13 Request Entity Too Large");
		break;
		case COAP_UNSUPPORTED_CONTENT_FORMAT:
			DBG("4.15 Unsupported Content-Format");
		break;
		case COAP_INTERNAL_SERVER_ERROR:
			DBG("5.00 Internal Server Error");
		break;
		case COAP_NOT_IMPLEMENTED:
			DBG("5.01 Not Implemented");
		break;
		case COAP_BAD_GATEWAY:
			DBG("5.02 Bad Gateway");
		break;
		case COAP_SERVICE_UNAVAILABLE:
			DBG("5.03 Service Unavailable");
		break;
		case COAP_GATEWAY_TIMEOUT:
			DBG("5.04 Gateway Timeout");
		break;
		case COAP_PROXYING_NOT_SUPPORTED:
			DBG("5.05 Proxying Not Supported");
		break;
	}
	// print token value
	// print options
	// print payload
}

int CoapPDU::getPDULength() {
	return _pduLength;
}

void CoapPDU::printPDUAsCArray() {
	for(int i=0; i<_pduLength; i++) {
		printf("0x%.2x, ",_pdu[i]);
	}
	printf("\r\n");
}

void CoapPDU::printOptionHuman(uint8_t *option) {
	// compute some useful stuff
	uint16_t optionDelta = getOptionDelta(option);
	uint16_t optionValueLength = getOptionValueLength(option);
	int extraDeltaBytes = computeExtraBytes(optionDelta);
	int extraValueLengthBytes = computeExtraBytes(optionValueLength);
	int totalLength = 1+extraDeltaBytes+extraValueLengthBytes+optionValueLength;

	if(totalLength>_pduLength) {
		totalLength = &_pdu[_pduLength-1]-option;
		DBG("New length: %u",totalLength);
	}

	// print summary
	DBG("~~~~~~ Option ~~~~~~");
	DBG("Delta: %u, Value length: %u",optionDelta,optionValueLength);

	// print all bytes
	DBG("All bytes (%d):",totalLength);
	for(int i=0; i<totalLength; i++) {
		if(i%4==0) {
			DBG(" ");
			DBGX("   %.2d ",i);
		}
		CoapPDU::printBinary(option[i]); DBGX(" ");
	}
	DBG(" "); DBG(" ");

	// print header byte
	DBG("Header byte:");
	DBGX("   ");
	CoapPDU::printBinary(*option++);
	DBG(" "); DBG(" ");

	// print extended delta bytes
	if(extraDeltaBytes) {
		DBG("Extended delta bytes (%d) in network order: ",extraDeltaBytes);
		DBGX("   ");
		while(extraDeltaBytes--) {
			CoapPDU::printBinary(*option++); DBGX(" ");
		}
	} else {
		DBG("No extended delta bytes");
	}
	DBG(" "); DBG(" ");

	// print extended value length bytes
	if(extraValueLengthBytes) {
		DBG("Extended value length bytes (%d) in network order: ",extraValueLengthBytes);
		DBGX("   ");
		while(extraValueLengthBytes--) {
			CoapPDU::printBinary(*option++); DBGX(" ");
		}
	} else {
		DBG("No extended value length bytes");
	}
	DBG(" ");

	// print option value
	DBG("Option value bytes:");
	for(int i=0; i<optionValueLength; i++) {
		if(i%4==0) {
			DBG(" ");
			DBGX("   %.2d ",i);
		}
		CoapPDU::printBinary(*option++);
		DBGX(" ");
	}
	DBG(" ");
}

uint16_t CoapPDU::getOptionValueLength(uint8_t *option) {
	uint16_t delta = (option[0] & 0xF0) >> 4;
	uint16_t length = (option[0] & 0x0F);
	// no extra bytes
	if(length<13) {
		return length;
	}
	
	// extra bytes skip header
	int offset = 1;
	// skip extra option delta bytes
	if(delta==13) {
		offset++;
	} else if(delta==14) {
		offset+=2;
	}

	// process length
	if(length==13) {
		return (option[offset]+13);
	} else {
		// need to convert to host order
		uint16_t networkOrder = 0x0000;
		networkOrder |= option[offset++];
		networkOrder <<= 8;
		networkOrder |= option[offset];
		uint16_t hostOrder = ntohs(networkOrder);
		return hostOrder+269;
	}

}

uint16_t CoapPDU::getOptionDelta(uint8_t *option) {
	uint16_t delta = (option[0] & 0xF0) >> 4;
	if(delta<13) {
		return delta;
	} else if(delta==13) {
		return (option[1]+13);
	} else {
		// need to convert to host order
		uint16_t networkOrder = 0x0000;
		networkOrder |= option[1];
		networkOrder <<= 8;
		networkOrder |= option[2];
		uint16_t hostOrder = ntohs(networkOrder);
		return hostOrder+269;
	}
}

int CoapPDU::getNumOptions() {
	return _numOptions;
}

/**
 * This returns the options as a sequence of structs.
 */
CoapPDU::CoapOption* CoapPDU::getOptions() {
	uint16_t optionDelta =0, optionNumber = 0, optionValueLength = 0;
	int totalLength = 0;

	if(_numOptions==0) {
		return NULL;
	}

	// malloc space for options
	CoapOption *options = (CoapOption*)malloc(_numOptions*sizeof(CoapOption));

	// first option occurs after token
	int optionPos = COAP_HDR_SIZE + getTokenLength();

	// walk over options and record information
	for(int i=0; i<_numOptions; i++) {
		// extract option details
		optionDelta = getOptionDelta(&_pdu[optionPos]);
		optionNumber += optionDelta;
		optionValueLength = getOptionValueLength(&_pdu[optionPos]);
		// compute total length
		totalLength = 1; // mandatory header
		totalLength += computeExtraBytes(optionDelta);
		totalLength += computeExtraBytes(optionValueLength);
		totalLength += optionValueLength;
		// record option details
		options[i].optionNumber = optionNumber;
		options[i].optionDelta = optionDelta;
		options[i].optionValueLength = optionValueLength;
		options[i].totalLength = totalLength;
		options[i].optionPointer = &_pdu[optionPos];
		options[i].optionValuePointer = &_pdu[optionPos+totalLength-optionValueLength];
		// move to next option
		optionPos += totalLength; 
	}
	return options;
}

int CoapPDU::findInsertionPosition(uint16_t optionNumber, uint16_t *prevOptionNumber) {
	// zero this for safety
	*prevOptionNumber = 0;

	// if option is bigger than any currently stored, it goes at the end
	// this includes the case that no option has yet been added
	if( (optionNumber >= _maxAddedOptionNumber) || (_pduLength == (COAP_HDR_SIZE+getTokenLength())) ) {
		*prevOptionNumber = _maxAddedOptionNumber;
		return _pduLength;
	}

	// otherwise walk over the options
	int optionPos = COAP_HDR_SIZE + getTokenLength();
	uint16_t optionDelta = 0, optionValueLength = 0;
	int currentOptionNumber = 0;
	while(optionPos<_pduLength && optionPos!=0xFF) {
		optionDelta = getOptionDelta(&_pdu[optionPos]);
		currentOptionNumber += optionDelta;
		optionValueLength = getOptionValueLength(&_pdu[optionPos]);
		// test if this is insertion position
		if(currentOptionNumber>optionNumber) {
			return optionPos;
		}
		// keep track of the last valid option number
		*prevOptionNumber = currentOptionNumber;
		// move onto next option
		optionPos += computeExtraBytes(optionDelta);
		optionPos += computeExtraBytes(optionValueLength);
		optionPos += optionValueLength;
		optionPos++; // (for mandatory option header byte)
	}
	return optionPos;

}

int CoapPDU::computeExtraBytes(uint16_t n) {
	if(n<13) {
		return 0;
	}

	if(n<269) { 
		return 1;
	}
	
	return 2;
}

// assumes space has been made
void CoapPDU::setOptionDelta(int optionPosition, uint16_t optionDelta) {
	int headerStart = optionPosition;
	// clear the old option delta bytes
	_pdu[headerStart] &= 0x0F;

	// set the option delta bytes
	if(optionDelta<13) {
		_pdu[headerStart] |= (optionDelta << 4);
	} else if(optionDelta<269) {
	   // 1 extra byte
		_pdu[headerStart] |= 0xD0; // 13 in first nibble
		_pdu[++optionPosition] &= 0x00;
		_pdu[optionPosition] |= (optionDelta-13);
	} else {
		// 2 extra bytes, network byte order uint16_t
		_pdu[headerStart] |= 0xE0; // 14 in first nibble
		optionDelta = htons(optionDelta-269);
		_pdu[++optionPosition] &= 0x00;
		_pdu[optionPosition] |= (optionDelta >> 8);     // MSB
		_pdu[++optionPosition] &= 0x00;
		_pdu[optionPosition] |= (optionDelta & 0x00FF); // LSB
	}
}

// inserts option, in-memory
// this requires that there is enough space at the location provided
int CoapPDU::insertOption(
	int insertionPosition,
	uint16_t optionDelta, 
	uint16_t optionValueLength,
	uint8_t *optionValue) {

	int headerStart = insertionPosition;

	// clear old option header start
	_pdu[headerStart] &= 0x00;

	// set the option delta bytes
	if(optionDelta<13) {
		_pdu[headerStart] |= (optionDelta << 4);
	} else if(optionDelta<269) {
	   // 1 extra byte
		_pdu[headerStart] |= 0xD0; // 13 in first nibble
		_pdu[++insertionPosition] &= 0x00;
		_pdu[insertionPosition] |= (optionDelta-13);
	} else {
		// 2 extra bytes, network byte order uint16_t
		_pdu[headerStart] |= 0xE0; // 14 in first nibble
		optionDelta = htons(optionDelta-269);
		_pdu[++insertionPosition] &= 0x00;
		_pdu[insertionPosition] |= (optionDelta >> 8);     // MSB
		_pdu[++insertionPosition] &= 0x00;
		_pdu[insertionPosition] |= (optionDelta & 0x00FF); // LSB
	}

	// set the option value length bytes
	if(optionValueLength<13) {
		_pdu[headerStart] |= (optionValueLength & 0x000F);
	} else if(optionValueLength<269) {
		_pdu[headerStart] |= 0x0D; // 13 in second nibble
		_pdu[++insertionPosition] &= 0x00;
		_pdu[insertionPosition] |= (optionValueLength-13);
	} else {
		_pdu[headerStart] |= 0x0E; // 14 in second nibble
		// this is in network byte order
		DBG("optionValueLength: %u",optionValueLength);
		uint16_t networkOrder = htons(optionValueLength-269);
		_pdu[++insertionPosition] &= 0x00;
		_pdu[insertionPosition] |= (networkOrder >> 8);     // MSB
		_pdu[++insertionPosition] &= 0x00;
		_pdu[insertionPosition] |= (networkOrder & 0x00FF); // LSB
	}

	// and finally copy the option value itself
	memcpy(&_pdu[++insertionPosition],optionValue,optionValueLength);

	return 0;
}

int CoapPDU::addOption(uint16_t insertedOptionNumber, uint16_t optionValueLength, uint8_t *optionValue) {
	// this inserts the option in memory, and re-computes the deltas accordingly
	// prevOption <-- insertionPosition
	// nextOption

	// find insertion location and previous option number
	uint16_t prevOptionNumber = 0; // option number of option before insertion point
	int insertionPosition = findInsertionPosition(insertedOptionNumber,&prevOptionNumber);
	DBG("inserting option at position %d, after option with number: %d",insertionPosition,prevOptionNumber);

	// compute option delta length
	uint16_t optionDelta = insertedOptionNumber-prevOptionNumber;
	uint8_t extraDeltaBytes = computeExtraBytes(optionDelta);

	// compute option length length
	uint16_t extraLengthBytes = computeExtraBytes(optionValueLength);

	// compute total length of option
	uint16_t optionLength = COAP_OPTION_HDR_BYTE + extraDeltaBytes + extraLengthBytes + optionValueLength;

	// if this is at the end of the PDU, job is done, just malloc and insert
	if(insertionPosition==_pduLength) {
		DBG("Inserting at end of PDU");
		// optionNumber must be biggest added
		_maxAddedOptionNumber = insertedOptionNumber;

		// set new PDU length and allocate space for extra option
		_pduLength += optionLength;
		uint8_t *newMemory = (uint8_t*)realloc(_pdu,_pduLength);
		if(newMemory==NULL) {
			// malloc failed
			return 1;
		}
		_pdu = newMemory;
		
		// insert option at position
		insertOption(insertionPosition,optionDelta,optionValueLength,optionValue);
		_numOptions++;
		return 0;
	}
	// XXX could do 0xFF pdu payload case for changing of dynamically allocated application space SDUs

	// the next option might (probably) needs it's delta changing
	// I want to take this into account when allocating space for the new
	// option, to avoid having to do two mallocs, first get info about this option
	int nextOptionDelta = getOptionDelta(&_pdu[insertionPosition]);
	int nextOptionNumber = prevOptionNumber + nextOptionDelta;
	int nextOptionDeltaBytes = computeExtraBytes(nextOptionDelta);
	// recompute option delta, relative to inserted option
	int newNextOptionDelta = nextOptionNumber-insertedOptionNumber;
	int newNextOptionDeltaBytes = computeExtraBytes(newNextOptionDelta);
	// determine adjustment
	int optionDeltaAdjustment = newNextOptionDeltaBytes-nextOptionDeltaBytes;
	

	// create space for new option, including adjustment space for option delta
	#ifdef DEBUG
	printBin();
	#endif
	DBG("Creating space");
	int mallocLength = optionLength+optionDeltaAdjustment;
	_pduLength += mallocLength;
	uint8_t *newMemory = (uint8_t*)realloc(_pdu,_pduLength);
	if(newMemory==NULL) { return 1; }
	_pdu = newMemory;

	// move remainder of PDU data up to create hole for new option
	#ifdef DEBUG
	printBin();
	#endif
	DBG("Shifting PDU.");
	shiftPDUUp(mallocLength,_pduLength-(insertionPosition+mallocLength));
	#ifdef DEBUG
	printBin();
	#endif

	// adjust option delta bytes of following option
	// move the option header to the correct position
	int nextHeaderPos = insertionPosition+mallocLength;
	_pdu[nextHeaderPos-optionDeltaAdjustment] = _pdu[nextHeaderPos];
	nextHeaderPos -= optionDeltaAdjustment;
	// and set the new value
	setOptionDelta(nextHeaderPos, newNextOptionDelta);

	// new option shorter
	// p p n n x x x x x
	// p p n n x x x x x -
	// p p - n n x x x x x
	// p p - - n x x x x x
	// p p o o n x x x x x

	// new option longer
	// p p n n x x x x x
	// p p n n x x x x x - - -
	// p p - - - n n x x x x x
	// p p - - n n n x x x x x
	// p p o o n n n x x x x x


	// now insert the new option into the gap
	DBGX("Inserting new option...");
	insertOption(insertionPosition,optionDelta,optionValueLength,optionValue);
	DBG("done");
	#ifdef DEBUG
	printBin();
	#endif

	// done, mark it with B! 
	return 0;
}

void CoapPDU::printHex() {
	printf("Hexdump dump of PDU\r\n");
	printf("%.2x %.2x %.2x %.2x",_pdu[0],_pdu[1],_pdu[2],_pdu[3]);
}

void CoapPDU::printBin() {
	for(int i=0; i<_pduLength; i++) {
		if(i%4==0) {
			printf("\r\n");
			printf("%.2d ",i);
		} 
		CoapPDU::printBinary(_pdu[i]); printf(" ");
	}
	printf("\r\n");
}

void CoapPDU::printBinary(uint8_t b) {
	printf("%d%d%d%d%d%d%d%d",
		(b&0x80)&&0x01,
		(b&0x40)&&0x01,
		(b&0x20)&&0x01,
		(b&0x10)&&0x01,
		(b&0x08)&&0x01,
		(b&0x04)&&0x01,
		(b&0x02)&&0x01,
		(b&0x01)&&0x01);
}

void CoapPDU::print() {
	fwrite(_pdu,1,_pduLength,stdout);
}
