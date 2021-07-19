#ifndef LOG_H
#define LOG_H

#include <stdio.h>
#include <time.h>
#include <string.h>
#include <systemd/sd-journal.h>
#include "../deps/b64/b64.h"

static const char *ipsec_log = "log/ipsec.log";
static const char *main_log = "log/monitor.log";
static const char *tunnel_log = "log/tunnels.log";

void write_log(char* file_name,char*log,int priority);

void get_current_time(char* buf);

int find(char* string, char* substr,int offset);

#endif