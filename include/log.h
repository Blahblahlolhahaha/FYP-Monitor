#ifndef LOG_H
#define LOG_H

#include <stdio.h>
#include <time.h>

static const char *ipsec_log = "log/ipsec.log";
static const char *main_log = "log/monitor.log";
static char* current_time;
void write_log(char* file_name,char*log);

void get_current_time(char* buf);

#endif