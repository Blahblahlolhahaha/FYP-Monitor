#include "../include/log.h"
#include <dirent.h>
#include <errno.h>

void write_log(char* file_name,char log[],int priority){
    DIR* dir = opendir(directory);
    if (ENOENT == errno) {
        /* Directory does not exist. */
        mkdir(directory, 0700);
    } 
    sd_journal_print(priority,"%s",log);
    FILE* fp = fopen(file_name, "a+");
    fprintf(fp,"%s",log);
    fclose(fp);
    
}

void get_current_time(char* buf){
    time_t rawtime;
    struct tm * timeinfo;

    time ( &rawtime );
    timeinfo = localtime ( &rawtime );

    sprintf(buf, "%02d/%02d/%04d %02d:%02d:%02d",timeinfo->tm_mday, timeinfo->tm_mon + 1, timeinfo->tm_year + 1900, timeinfo->tm_hour, timeinfo->tm_min, timeinfo->tm_sec);

}

int find(char* string, char* substr,int offset){
    char* pointer = strstr(string + offset,substr);
    if(pointer == NULL){
        return -1;
    }
    else{
        return pointer - string;
    }
}

