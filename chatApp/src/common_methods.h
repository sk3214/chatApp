#ifndef HEADER_FILE
#define HEADER_FILE
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/types.h>
// #include <sys/time.h>
#include <sys/select.h>
#include <arpa/inet.h>
#include <netdb.h>
#include "../include/logger.h"

struct clientData
{
    char ip[20];
    int port;
};

// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET)
    {
        return &(((struct sockaddr_in *)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6 *)sa)->sin6_addr);
}

void swap(struct clientData * xp, struct clientData* yp)
{
    struct clientData temp = *xp;
    *xp = *yp;
    *yp = temp;
}

void sort(struct clientData *arr, int n)
{
    int i, j, min_idx;
 
    for (i = 0; i < n - 1; i++) {
        min_idx = i;
        for (j = i + 1; j < n; j++)
        if (arr[j].port < arr[min_idx].port)
            min_idx = j;

        swap(&arr[min_idx], &arr[i]);
    }
}

void initClientList(int *clientList){
    struct sockaddr_storage cp = {0};
    // printf("In initCLientList\n");
    for (int i = 0; i < 30; i++)
        clientList[i] = 0;
}

void addClient(int *client, int *clientList)
{
    int i;
    char myIP[16];
    struct sockaddr_in _address;
    _address = *(struct sockaddr_in *)client;
    struct sockaddr_storage cp = {0};
    // printf("Adding Client\n");
    for (i = 0; i < 30; i++)
    {
        if (clientList[i] == 0)
        {
            printf("Adding to list of sockets as %d\n", i);
            clientList[i] = *client;
            break;
        }
    }
    // printf("Client Added\n");
}

void removeClient(int *client, int *clientList)
{
    struct sockaddr_storage cp = {0};
    for (int i = 0; i < 30; i++)
    {
        if (clientList[i] == *client)
        {
            clientList[i] = 0;
            // free(client);
            break;
        }
    }
}

void getIP(void)
{

    int _socket;
    struct sockaddr_in _address, my_addr;
    char myIP[16];
    socklen_t sin_size;
    _address.sin_family = AF_INET;
    _address.sin_port = htons(53);
    _address.sin_addr.s_addr = inet_addr("8.8.8.8");

    if ((_socket = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
    {
        printf("UDP socket error");
    }

    bind(_socket, (struct sockaddr *)&_address, sizeof(_address));

    connect(_socket, (struct sockaddr *)&_address, sizeof(_address));
    sin_size = sizeof my_addr;
    bzero(&my_addr, sizeof(my_addr));
    getsockname(_socket, (struct sockaddr *)&_address, &sin_size);

    inet_ntop(AF_INET, &_address.sin_addr, myIP, sizeof(myIP));
    cse4589_print_and_log("IP:%s\n", myIP);

    close(_socket);
}

void getPort(struct sockaddr_in *socket_addr)
{
    int myPort;
    myPort = ntohs(socket_addr->sin_port);
    cse4589_print_and_log("PORT:%u\n", myPort);
}

void getAuthor(void)
{
    cse4589_print_and_log("I, %s, have read and understood the course academic integrity policy.\n", "mohamma9");
}
void listClients(int *clientList)
{
    struct sockaddr_storage cp = {0};
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    int count = 0;
    char ip[20];
    char host[256];
    for(int i=0;i<30;i++){
        if(clientList[i] !=0){
            getpeername(clientList[i],(struct sockaddr *)&addr, &addr_len);
            memcpy(ip,inet_ntoa(addr.sin_addr),sizeof(ip));
            if(strcmp(ip,"128.205.36.46")==0){
                strcpy(host,"stones.cse.buffalo.edu");
            }
            else if(strcmp(ip,"128.205.36.35")==0){
                strcpy(host,"embankment.cse.buffalo.edu");
            }
            else if(strcmp(ip,"128.205.36.33")==0){
                strcpy(host,"highgate.cse.buffalo.edu");
            }
            else if(strcmp(ip,"128.205.36.34")==0){
                strcpy(host,"euston.cse.buffalo.edu");
            }
            else if(strcmp(ip,"128.205.36.8")==0){
                strcpy(host,"timberlake.cse.buffalo.edu");
            }
            else if(strcmp(ip,"128.205.36.36")==0){
                strcpy(host,"underground.cse.buffalo.edu");
            }
            else {
                strcpy(host,"docker");
            }
            cse4589_print_and_log("%-5d%-35s%-20s%-8d\n", (count + 1), host, ip, ntohs(addr.sin_port));
            // printf("Peer IP address: %s\n", inet_ntoa(addr.sin_addr));
            // printf("Peer port      : %u\n", ntohs(addr.sin_port));
            count++;
        }
    }
    if (count == 0)
    {
        printf("No clients connected\n");
    }
}

void listBlockedClients(int *clientList,char *blockedIp, int* count)
{
    struct sockaddr_storage cp = {0};
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    struct clientData data[30];
    // int count = 0;
    char ip[20];
    char host[256];

    for (int i = 0; i < 30; i++)
    {
        // data[i] = clientList[i];
        struct sockaddr_in addr, clientInfo;
        socklen_t addr_len = sizeof(addr);
        struct hostent *he;
        if(clientList[i]!=0){
            getpeername(clientList[i],(struct sockaddr *)&addr,&addr_len);
            memcpy(&clientInfo,&addr,addr_len);
            memcpy(data[i].ip,inet_ntoa(clientInfo.sin_addr),sizeof(data[i].ip));
            data[i].ip[20] = '\0';
            data[i].port = clientInfo.sin_port;
        }
        else
        {
            memcpy(data[i].ip, "", sizeof(data[i].ip));
            data[i].ip[20] = '\0';
            data[i].port = 0;
        }
    }
    sort(data,30);
    for(int i=0;i<30;i++){
        if(strlen(data[i].ip)>0 && data[i].port!=0){
            // getpeername(clientList[i],(struct sockaddr *)&addr, &addr_len);
            // memcpy(ip,inet_ntoa(addr.sin_addr),sizeof(ip));
            if(strcmp(blockedIp,data[i].ip)==0){
                if(strcmp(data[i].ip,"128.205.36.46")==0){
                strcpy(host,"stones.cse.buffalo.edu");
                }
                else if(strcmp(data[i].ip,"128.205.36.35")==0){
                    strcpy(host,"embankment.cse.buffalo.edu");
                }
                else if(strcmp(data[i].ip,"128.205.36.33")==0){
                    strcpy(host,"highgate.cse.buffalo.edu");
                }
                else if(strcmp(data[i].ip,"128.205.36.34")==0){
                    strcpy(host,"euston.cse.buffalo.edu");
                }
                else if(strcmp(data[i].ip,"128.205.36.8")==0){
                    strcpy(host,"timberlake.cse.buffalo.edu");
                }
                else if(strcmp(data[i].ip,"128.205.36.36")==0){
                    strcpy(host,"underground.cse.buffalo.edu");
                }
                else {
                    strcpy(host,"docker");
                }
                cse4589_print_and_log("%-5d%-35s%-20s%-8d\n", (*count + 1), host, data[i].ip, data[i].port);
                // printf("Peer IP address: %s\n", inet_ntoa(addr.sin_addr));
                // printf("Peer port      : %u\n", ntohs(addr.sin_port));
                *count++;
            }
        }
    }
}

void sendClientList(int *client, int *clientList)
{
    struct clientData data[30];
    char ip[20];
    unsigned char *char_data;
    unsigned char *prepend = (char *)"LIST ";
    unsigned char dataToSend[sizeof(prepend) + sizeof(data)];

    for (int i = 0; i < 30; i++)
    {
        // data[i] = clientList[i];
        struct sockaddr_in addr, clientInfo;
        socklen_t addr_len = sizeof(addr);
        struct hostent *he;
        if(clientList[i]!=0){
            getpeername(clientList[i],(struct sockaddr *)&addr,&addr_len);
            memcpy(&clientInfo,&addr,addr_len);
            memcpy(data[i].ip,inet_ntoa(clientInfo.sin_addr),sizeof(data[i].ip));
            data[i].ip[20] = '\0';
            data[i].port = clientInfo.sin_port;
        }
        else
        {
            memcpy(data[i].ip, "", sizeof(data[i].ip));
            data[i].ip[20] = '\0';
            data[i].port = 0;
        }
    }
    strcpy(dataToSend, prepend);
    char_data = (char *)&data;
    memcpy(dataToSend + strlen(prepend), char_data, sizeof(data));
    send(*client, dataToSend, sizeof(dataToSend), 0);
}

void receiveClientList(char *data, struct clientData *clientList)
{
    struct clientData receivedData[30];
    memcpy(receivedData, data, sizeof(receivedData));
    // printf()
    // printf("Receiving list of clients\n");
    for (int i = 0; i < 30; i++)
    {
        memcpy(clientList[i].ip, receivedData[i].ip, sizeof(clientList[i].ip));
        clientList[i].port = ntohs(receivedData[i].port);
    }
    // send(*client,data, sizeof(data),0);
    // printf("Received list of clients\n");
}

void listClientsForClient(struct clientData *data){
    struct clientData sortedData[30];
    memcpy(sortedData,data,sizeof(sortedData));
    sort(sortedData,30);
    int count =0;
    for(int  i=0;i<30;i++){
        char host[256];
        // printf("%d\n",strlen(data[i].ip));
        if(strlen(sortedData[i].ip)>0 && sortedData[i].port!=0){
            count++;
            if(strcmp(sortedData[i].ip,"128.205.36.46")==0){
                strcpy(host,"stones.cse.buffalo.edu");
            }
            else if(strcmp(sortedData[i].ip,"128.205.36.35")==0){
                strcpy(host,"embankment.cse.buffalo.edu");
            }
            else if(strcmp(sortedData[i].ip,"128.205.36.33")==0){
                strcpy(host,"highgate.cse.buffalo.edu");
            }
            else if(strcmp(sortedData[i].ip,"128.205.36.34")==0){
                strcpy(host,"euston.cse.buffalo.edu");
            }
            else if(strcmp(sortedData[i].ip,"128.205.36.8")==0){
                strcpy(host,"timberlake.cse.buffalo.edu");
            }
            else if(strcmp(sortedData[i].ip,"128.205.36.36")==0){
                strcpy(host,"underground.cse.buffalo.edu");
            }
            else {
                strcpy(host,"docker");
            }
            cse4589_print_and_log("%-5d%-35s%-20s%-8d\n", count, host, sortedData[i].ip, sortedData[i].port);
        }
    }
}

void trim_newline(char *text)
{
    int len = strlen(text) - 1;
    if (text[len] == '\n')
    {
        text[len] = '\0';
    }
}

int sendMessage(int *fd, char *msg)
{
    unsigned char *ip = strsep(&msg, " ");
    trim_newline(ip);
    trim_newline(msg);
    unsigned char *data = msg;
    unsigned char *prepend = (char *)"SEND ";
    unsigned char *separator = (char *)"-";
    unsigned char dataToSend[sizeof(prepend) + sizeof(ip) + sizeof(separator) + 2048 + 5];

    // printf("%s,%s,%d\n",ip,msg,sizeof(dataToSend));

    strcpy(dataToSend, prepend);
    strcat(dataToSend, ip);
    strcat(dataToSend, separator);
    strcat(dataToSend, msg);
    if(send(*fd,dataToSend, sizeof(dataToSend),0)<0){
        perror("Error to send data");
        return 1;
    }
    return 0;
}
#endif
