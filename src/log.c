#include "../include/log.h"
#include <openssl/md5.h>
#include <openssl/sha.h>

void hash(unsigned char *buffer, unsigned char** hash){

    unsigned char md5_digest[MD5_DIGEST_LENGTH];
    int i;

    MD5(buffer, strlen(buffer), md5_digest);


    unsigned char *md5_hash = calloc(MD5_DIGEST_LENGTH*2,1);
    for (i = 0; i < MD5_DIGEST_LENGTH; i++) {
        snprintf(md5_hash+strlen(md5_hash),2,"%02x", md5_digest[i]);
    }
    strcpy(*hash,md5_hash);
    free(md5_hash);
    

}

void init_hash(){
            FILE* f22 = fopen(ipsec_log, "rb");
            if(f22){
                fseek(f22, 0, SEEK_END);
                long fsize = ftell(f22);
                fseek(f22, 0, SEEK_SET);  /* same as rewind(f); */
                char *string2 = calloc(fsize + 1,1);
                if(string2){
                    fread(string2, 1, fsize, f22);
                    fclose(f22);
                    string2[fsize] = 0;
                    non_ipsec_hash = calloc(MD5_DIGEST_LENGTH*2,1);
                    hash(string2,&non_ipsec_hash);
                }
            }
            FILE* f23 = fopen(main_log, "rb");
            if(f23){
                fseek(f23, 0, SEEK_END);
                long fsize = ftell(f23);
                fseek(f23, 0, SEEK_SET);  /* same as rewind(f); */
                char *string23 = calloc(fsize + 1,1);
                if(string23){
                    fread(string23, 1, fsize, f23);
                    fclose(f23);
                    string23[fsize] = 0;
                    tampered_hash = calloc(MD5_DIGEST_LENGTH*2,1);
                    hash(string23,&tampered_hash);
                }
            }
                
            
}


void write_log(char* file_name,char log[], char** loghash){
    FILE *f = fopen(file_name, "rb");
    if(f){
        fseek(f, 0, SEEK_END);
        long fsize = ftell(f);
        fseek(f, 0, SEEK_SET);  /* same as rewind(f); */
        char *string = calloc(fsize + 1,1);
        if(string){
            fread(string, 1, fsize, f);
            fclose(f);

            string[fsize] = 0;
            unsigned char *currenthash = calloc(MD5_DIGEST_LENGTH*2,1);
            hash(string,&currenthash);
                // printf("%s\n",currenthash);
            if(strcmp(currenthash,*loghash)==0){
                // printf("Logged incident");
                FILE* fp = fopen(file_name, "a+");
                if(fp){
                    fprintf(fp,"%s",log);
                    fclose(fp);
                }
                FILE* f2 = fopen(file_name, "rb");
                if(f2){
                    fseek(f2, 0, SEEK_END);
                    fsize = ftell(f2);
                    fseek(f2, 0, SEEK_SET);  /* same as rewind(f); */
                    char *string2 = calloc(fsize + 1,1);
                    if(string2){
                        fread(string2, 1, fsize, f2);
                        fclose(f2);
                        string2[fsize] = 0;
                        *loghash = calloc(MD5_DIGEST_LENGTH*2,1);
                        hash(string2,loghash);

                        free(string);
                        free(string2);
                        

                    }

                }
            }else{
                printf("Log has been tampered with.\nTampered File: %s\nOriginal log hash: %s\nCurrent log hash: %s\n",file_name,*loghash,currenthash);
                exit(0);
            }

        }
 
    }

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

