#include "../include/log.h"

void write_log(char* file_name,char log[]){
    FILE* fp = fopen(file_name, "a+");
    fprintf(fp,"%s",log);
    fclose(fp);
    
}

void get_current_time(char* buf){
    time_t rawtime;
    struct tm * timeinfo;

    time ( &rawtime );
    timeinfo = localtime ( &rawtime );
    sprintf(buf, "%d/%d/%d %d:%d:%d",timeinfo->tm_mday, timeinfo->tm_mon + 1, timeinfo->tm_year + 1900, timeinfo->tm_hour, timeinfo->tm_min, timeinfo->tm_sec);
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

