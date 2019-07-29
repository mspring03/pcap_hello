#include <stdio.h>
#include <stdint.h>
#include <pcap.h>
#include <arpa/inet.h>
#include "protocol/all.h"
#include <string.h>

const char *HT_METHOD_HTTP = "HTTP";
const char *HT_METHOD_GET = "GET";
const char *HT_METHOD_POST = "POST";
const char *HT_METHOD_PUT = "PUT";
const char *HT_METHOD_DELETE = "DELETE";
const char *HT_METHOD_CONNECT = "CONNECT";
const char *HT_METHOD_OPTIONS = "OPTIONS";
const char *HT_METHOD_TRACE = "TRACE";
const char *HT_METHOD_PATCH = "PATCH";

void *HTTP_METHOD[] =
{
    (void *)HT_METHOD_HTTP,
    (void *)HT_METHOD_GET,
    (void *)HT_METHOD_POST,
    (void *)HT_METHOD_PUT,
    (void *)HT_METHOD_DELETE,
    (void *)HT_METHOD_CONNECT,
    (void *)HT_METHOD_OPTIONS,
    (void *)HT_METHOD_TRACE,
    (void *)HT_METHOD_PATCH
};

void cheakhttp(const u_char *data)
{
    int i,j;
    char cheak[7];

    for(i = 0;i < 2;i++){
        for(j = 0;j < 6; j++){
                cheak[j] = data[j];
            }
        int num = memcmp((const char *)cheak,(char *)(HTTP_METHOD[i]),3);
        if(num == 0){
            printf("http\n");
            printf("http_method: %s\n",HTTP_METHOD[i]);
        } 
    }
    // printf("\n%s",cheak);
    // printf("%s",data);
    
}
