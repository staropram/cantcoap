#pragma once
#include <stdio.h>

//DEBUG define is  handled in  Makefile
//#undef DEBUG

#define DBG_NEWLINE "\n"

#define INFO(...) printf(__VA_ARGS__); printf(DBG_NEWLINE);
#define INFOX(...); printf(__VA_ARGS__);
#define ERR(...) printf(__VA_ARGS__); printf(DBG_NEWLINE);

#ifdef DEBUG
	#define DBG(...) fprintf(stderr,"%s:%d ",__FILE__,__LINE__); fprintf(stderr,__VA_ARGS__); fprintf(stderr,"\r\n");
	#define DBGX(...) fprintf(stderr,__VA_ARGS__);
	#define DBGLX(...) fprintf(stderr,"%s:%d ",__FILE__,__LINE__); fprintf(stderr,__VA_ARGS__);
	#define DBG_PDU() printBin();
#else
	#define DBG(...) {};
	#define DBGX(...) {};
	#define DBGLX(...) {};
	#define DBG_PDU() {};
#endif
