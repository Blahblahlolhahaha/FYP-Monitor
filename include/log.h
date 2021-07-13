#ifndef LOG_H
#define LOG_H

#include <stdio.h>
#include <time.h>
#include <string.h>
#include "../deps/b64/b64.h"

static const char *ipsec_log = "log/ipsec.log";
static const char *main_log = "log/monitor.log";
static const char *tunnel_log = "log/tunnels.log";
unsigned char *non_ipsec_hash;
unsigned char *tampered_hash;
void write_log(char* file_name,char log[], char** loghash);
void get_current_time(char* buf);

int find(char* string, char* substr,int offset);

void hash(unsigned char *buffer, unsigned char** hash);
void init_hash();

#endif