#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include "../include/logger.h"
#include "common_methods.h"

#include <arpa/inet.h>

#define MAXDATASIZE 8046 // max number of bytes we can get at once

struct sockaddr_in *client;
int clientSock, databytes, serverSock, temp, max_descriptors;
int clientListFD[30];
struct clientData listOfClients[30] = {0};
char blockedList[30][20];
int loggedIn = 0;
int msg_count = 0;
struct timeval tv;
fd_set read_descriptors;
struct sockaddr_in client_address, sock_address;
struct addrinfo *server, hints;

void Broadcast(char *msg);

int login(char *data)
{
    char serverIP[16];
    char *ip, *port;
    memset(&hints, 0, sizeof hints);
    ip = strsep(&data, " ");
    port = data;
    trim_newline(ip);
    trim_newline(port);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    clientSock = socket(AF_INET, SOCK_STREAM, 0);
    struct timeval tv = {0, 500};
    ;
    int yes = 1;

    // tv.tv_sec = 1
    // tv.tv;  /* 3 Secs Timeout */
    setsockopt(clientSock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));
    setsockopt(clientSock, SOL_SOCKET, SO_RCVTIMEO, (struct timeval *)&tv, sizeof(struct timeval));
    if (clientSock < 0)
    {
        // perror("Client: socket");
        return 1;
    }

    if ((temp = getaddrinfo(ip, port, &hints, &server)) != 0)
    {
        // fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(temp));
        close(clientSock);
        return 1;
    }
    bind(clientSock, (struct sockaddr *)&client_address, sizeof(client_address));
    if ((temp = connect(clientSock, server->ai_addr, server->ai_addrlen)) < 0)
    {
        // perror("Client: server connect\n");
        // printf("Error\n");
        // fprintf(stderr, "Server Connect: %s\n", gai_strerror(temp));
        close(clientSock);
        return 1;
    }
    initClientList(clientListFD);
    fflush(stdout);
    // inet_ntop(AF_INET, &server->ai_addr, serverIP, sizeof(serverIP));
    printf("Connected to server\n");
    loggedIn = 1;
    return 0;
}

void logout()
{
    close(clientSock);
    // free(&clientList);
    loggedIn = 0;
    msg_count = 0;
    printf("Logged out from server\n");
}

void exitChat()
{
    if (loggedIn)
        logout();
    exit(0);
}

void refreshClients(char *msg)
{
    send(clientSock, msg, sizeof(msg), 0);
}

int handleBlock(int *client,char * ip){
    int client_found = 0;
    int count = 0;
    unsigned char *char_data;
    unsigned char *prepend = (char *)"BLOCK ";
    unsigned char dataToSend[sizeof(prepend) + 20];

    struct sockaddr_in sa;
    int result = inet_pton(AF_INET, ip, &(sa.sin_addr));
    printf("Result: %d\n",result);
    if(result <= 0){
        cse4589_print_and_log("[%s:ERROR]\n", "BLOCK");
        return 1;
    }
    for(int i = 0;i<30;i++){
        if(strcmp(listOfClients->ip,ip)==0)
            count+=1;
    }
    if(count == 0){
        cse4589_print_and_log("[%s:ERROR]\n", "BLOCK");
        return 1;
    }
    for (int i = 0; i < 30; i++)
    {
        if (strlen(blockedList[i]) != 0 && strcmp(blockedList[i], ip) == 0)
        {
            // printf("Found client\n");
            client_found = 1;
            cse4589_print_and_log("[%s:ERROR]\n", "BLOCK");
            break;
        }
    }
    if(client_found == 1)
        return 1;
    else if (client_found == 0)
    {
        for (int i = 0; i < 30; i++)
        {
            if (strlen(blockedList[i]) == 0)
            {
                strcpy(blockedList[i], ip);
                break;
            }
        }
        strcpy(dataToSend, prepend);
        strcat(dataToSend, ip);

        if(send(*client,dataToSend, sizeof(dataToSend),0)<0){
            cse4589_print_and_log("[%s:ERROR]\n", "BLOCK");
            perror("Error to send data");
        }
        else
            cse4589_print_and_log("[%s:SUCCESS]\n", "BLOCK");
    }
}

int handleUnblock(int *client,char * ip){
    int client_found = 0;
    int count = 0;
    unsigned char *char_data;
    unsigned char *prepend = (char *)"UNBLOCK ";
    unsigned char dataToSend[sizeof(prepend) + 20];

    struct sockaddr_in sa;
    int result = inet_pton(AF_INET, ip, &(sa.sin_addr));
    printf("Result: %d\n",result);
    if(result <= 0){
        cse4589_print_and_log("[%s:ERROR]\n", "UNBLOCK");
        return 1;
    }
    for(int i = 0;i<30;i++){
        if(strcmp(listOfClients->ip,ip)==0)
            count+=1;
    }
    if(count == 0){
        cse4589_print_and_log("[%s:ERROR]\n", "UNBLOCK");
        return 1;
    }
    for (int i = 0; i < 30; i++)
    {
        if (strlen(blockedList[i]) != 0 && strcmp(blockedList[i], ip) == 0)
        {
            // printf("Found client\n");
            client_found = 1;
            break;
        }
    }
    if(client_found == 0){
        cse4589_print_and_log("[%s:ERROR]\n", "UNBLOCK");
        return 1;
    }
    else if (client_found == 1)
    {
        for (int i = 0; i < 30; i++)
        {
            if (strcmp(blockedList[i],ip) == 0)
            {
                strcpy(blockedList[i], "");
                break;
            }
        }
        strcpy(dataToSend, prepend);
        strcat(dataToSend, ip);

        if(send(*client,dataToSend, sizeof(dataToSend),0)<0){
            cse4589_print_and_log("[%s:ERROR]\n", "UNBLOCK");
            perror("Error to send data");
        }
        else
            cse4589_print_and_log("[%s:SUCCESS]\n", "UNBLOCK");
    }
}

void handleReceiveData(char *msg)
{
    char *token;
    token = strsep(&msg, "-");
    trim_newline(token);
    cse4589_print_and_log("[%s:SUCCESS]\n", "RECEIVED");
    cse4589_print_and_log("msg from:%s\n[msg]:%s\n", token, msg);
    cse4589_print_and_log("[%s:END]\n", "RECEIVED");
}

void parse_client_user_input(char *s)
{
    char *token;
    token = strsep(&s, " ");
    trim_newline(token);

    if (strcmp(token, "IP") == 0)
    {
        cse4589_print_and_log("[%s:SUCCESS]\n", "IP");
        getIP();
        cse4589_print_and_log("[%s:END]\n", "IP");
    }
    else if (strcmp(token, "PORT") == 0)
    {
        cse4589_print_and_log("[%s:SUCCESS]\n", "PORT");
        getPort(client);
        cse4589_print_and_log("[%s:END]\n", "PORT");
    }
    else if (strcmp(token, "AUTHOR") == 0)
    {
        cse4589_print_and_log("[%s:SUCCESS]\n", "AUTHOR");
        getAuthor();
        cse4589_print_and_log("[%s:END]\n", "AUTHOR");
    }
    else if (strcmp(token, "LIST") == 0)
    {
        if (loggedIn)
        {
            cse4589_print_and_log("[%s:SUCCESS]\n", "LIST");
            listClientsForClient(listOfClients);
            cse4589_print_and_log("[%s:END]\n", "LIST");
        }
        // listClients(clientList);
        else
        {
            cse4589_print_and_log("[%s:ERROR]\n", "LIST");
            // printf("Login to the server.\n");
            cse4589_print_and_log("[%s:END]\n", "LIST");
        }
        // listClients();
    }
    else if (strcmp(token, "REFRESH") == 0)
    {
        if (loggedIn)
        {
            cse4589_print_and_log("[%s:SUCCESS]\n", "REFRESH");
            refreshClients(token);
            cse4589_print_and_log("[%s:END]\n", "REFRESH");
        }
        else
        {
            cse4589_print_and_log("[%s:ERROR]\n", "REFRESH");
            printf("Login to the server.\n");
            cse4589_print_and_log("[%s:END]\n", "REFRESH");
        }
    }
    else if (strcmp(token, "SEND") == 0)
    {
        int status = sendMessage(&clientSock, s);
        if(status == 0)
            cse4589_print_and_log("[%s:SUCCESS]\n", "SEND");
        else if(status == 1)
            cse4589_print_and_log("[%s:ERROR]\n", "SEND");
        cse4589_print_and_log("[%s:END]\n", "SEND");
    }
    else if (strcmp(token, "BROADCAST") == 0)
    {
        cse4589_print_and_log("[%s:SUCCESS]\n", "BROADCAST");
        Broadcast(s);
        cse4589_print_and_log("[%s:END]\n", "BROADCAST");
    }
    else if (strcmp(token, "BLOCK") == 0)
    {
        handleBlock(&clientSock,s);
        cse4589_print_and_log("[%s:END]\n", "BLOCK");
    }
    else if (strcmp(token, "UNBLOCK") == 0)
    {
        handleUnblock(&clientSock,s);
        cse4589_print_and_log("[%s:END]\n", "UNBLOCK");
    }
    else if (strcmp(token, "LOGIN") == 0)
    {
        int i = login(s);
        if (i == 0)
        {
            cse4589_print_and_log("[%s:SUCCESS]\n", "LOGIN");
            cse4589_print_and_log("[%s:END]\n", "LOGIN");
        }
        else if (i == 1)
        {
            cse4589_print_and_log("[%s:ERROR]\n", "LOGIN");
            cse4589_print_and_log("[%s:END]\n", "LOGIN");
        }
    }
    else if (strcmp(token, "LOGOUT") == 0)
    {
        if (loggedIn)
        {
            cse4589_print_and_log("[%s:SUCCESS]\n", "LOGOUT");
            logout();
            cse4589_print_and_log("[%s:END]\n", "LOGOUT");
        }
        else
        {
            cse4589_print_and_log("[%s:ERROR]\n", "LOGOUT");
            cse4589_print_and_log("[%s:END]\n", "LOGOUT");
            // printf("You are not connected to any server\n");
        }
    }
    else if (strcmp(token, "EXIT") == 0)
    {
        cse4589_print_and_log("[%s:SUCCESS]\n", "EXIT");
        exitChat();
        cse4589_print_and_log("[%s:END]\n", "EXIT");
    }
    else
    {
        printf("Invalid Command\n");
    }
}

void parser_server_data(char *msg)
{
    char *token;
    // printf("Server data: %s\n",msg);
    token = strsep(&msg, " ");
    trim_newline(token);

    if (strcmp(token, "LIST") == 0)
    {
        receiveClientList(msg, listOfClients);
    }
    else if (strcmp(token, "SEND") == 0)
    {
        handleReceiveData(msg);
    }
}

void execute_command(char *command, char *data)
{
    printf("Inside execute_command");
    if (strcmp(command, "IP") == 0)
    {
        getIP();
    }
    else if (strcmp(command, "PORT") == 0)
    {
        getPort(client);
    }
    else
    {
        printf("Not a command");
    }
}

void start_client(int port)
{
    char buf[8046];
    int yes = 1;
    int msg_count = 0;
    tv.tv_sec = 0;
    tv.tv_usec = 500;
    client_address.sin_family = AF_INET;
    client_address.sin_addr.s_addr = INADDR_ANY;
    client_address.sin_port = htons(port);
    client = &client_address;
    puts("Client started");
    for(int i =0;i<30;i++){
        blockedList[i][20] = '\0';
    }

    while (1)
    {
        FD_ZERO(&read_descriptors);
        FD_SET(STDIN_FILENO, &read_descriptors);
        if (loggedIn)
        {
            FD_SET(clientSock, &read_descriptors);
            max_descriptors = clientSock;
        }
        else
        {
            max_descriptors = STDIN_FILENO;
        }
        fflush(stdin);
        // puts(">");
        select(max_descriptors + 1, &read_descriptors, NULL, NULL, NULL);

        if (FD_ISSET(STDIN_FILENO, &read_descriptors))
        {
            char msg[2048];
            memset(msg, 0, sizeof(msg));
            fgets(msg, 2048, stdin);
            trim_newline(msg);
            // printf("%s\n",msg);
            parse_client_user_input(msg);
        }
        else if (FD_ISSET(clientSock, &read_descriptors))
        {
            setsockopt(clientSock, SOL_SOCKET, SO_RCVTIMEO, (struct timeval *)&tv, sizeof(struct timeval));
            int index = 0;
            // Bytes read by the socket in one go
            ssize_t bytesRead;
            while (1)
            {
                // printf("Before\n");
                bytesRead = read(clientSock, buf + index, MAXDATASIZE);
                // printf("%u\n", bytesRead);
                if (bytesRead <= 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
                {
                    // perror("recv");
                    if (sizeof(buf) != 0)
                    {
                        // printf("Received all the data\n");
                        buf[index + 1] = '\0';
                        // printf("Client Receive: %s\n",buf);
                        parser_server_data(buf);
                    }
                    msg_count += 1;
                    break;
                }
                else
                {
                    // printf("Here\n");

                    index = index + bytesRead;
                    // printf("%d\n",index);
                }
            }
        }
        else
        {
            continue;
        }
    }
}

void Broadcast(char *msg)
{
    trim_newline(msg);
    unsigned char *data = msg;
    unsigned char *prepend = (char *)"BROADCAST ";
    unsigned char dataToSend[sizeof(prepend) + 2048 + 5];

    strcpy(dataToSend, prepend);
    strcat(dataToSend, msg);
    send(clientSock, dataToSend, sizeof(dataToSend), 0);
}
