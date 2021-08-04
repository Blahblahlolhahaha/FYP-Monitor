#ifndef LOG_H
#define LOG_H

#include <stdio.h>
#include <time.h>
#include <string.h>
#include <systemd/sd-journal.h>
#include "../deps/b64/b64.h"

/// IPsec log
static const char *ipsec_log = "log/ipsec.log";
/// Malicious traffic log
static const char *main_log = "log/monitor.log";
/// Saved tunnel log
static const char *tunnel_log = "log/tunnels.log";

/**
 * Write log into systemd log and a stored log file
 * @param file_name filename to write log to
 * @param log String to write to log
 * @param priority of the log
 */
void write_log(char* file_name,char*log,int priority);

/**
 * Gets current time in the format dd/mm/yyyy hh:MM:ss format
 * @param buf string to store the formatted string
 */
void get_current_time(char* buf);

/**
 * Gets position of a substring starting from a specified offset
 * @param string string to search for the substring
 * @param substr substring to search for
 * @param offset offset to start searching
 * @returns position of the substring. If not substring is not found, the function returns -1 
 */
int find(char* string, char* substr,int offset);

#endif