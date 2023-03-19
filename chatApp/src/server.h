#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/types.h>
// #include <sys/time.h>
#include "../include/logger.h"
#include "common_methods.h"
#include <sys/select.h>
#define MAX_SIZE 100

int server_socket, total_clients = 30, client_connections[30], client_socket, max_socket_descriptors,
                   addrlen, sd, valread;
struct sockaddr_storage clientList[30];
fd_set read_descriptors;
char buf[8046];
struct sockaddr_in server_address;
char clientData[30][sizeof(struct sockaddr_in)];
void handleBroadcast(int *client, char *msg);

struct messageQueue
{
    char ip[20];
    char messages[MAX_SIZE][512];
    int rear;
    int front;
};

struct clientStats
{
    char ip[20];
    int port;
    int message_sent_count;
    int message_receive_count;
};

struct clientsBlocked {
    char ip[20];
    int port;
    char block_list[30][20];
};

struct clientsBlocked blockList[30];

void initBlockList(int *client){
    int client_found = 0;
    struct sockaddr_in addr, clientInfo;
    socklen_t addr_len = sizeof(addr);
    char ip[20];
    getpeername(*client, (struct sockaddr *)&addr, &addr_len);
    memcpy(&clientInfo, &addr, addr_len);
    memcpy(ip, inet_ntoa(clientInfo.sin_addr), sizeof(ip));
    ip[20] = '\0';
    for (int i = 0; i < 30; i++)
    {
        if (strlen(blockList[i].ip) != 0 && strcmp(blockList[i].ip, ip) == 0)
        {
            // printf("Found client\n");
            client_found = 1;
            break;
        }
    }
    if (client_found == 0)
    {
        for (int i = 0; i < 30; i++)
        {
            if (strlen(blockList[i].ip) == 0)
            {
                strcpy(blockList[i].ip, ip);
                for (int j=0;j<30;j++)
                    blockList[i].block_list[j][20] = '\0';
                break;
            }
        }
    }
}

void handleBlockClient(int *client,char *blockip){
    int done = 0;
    struct sockaddr_in addr, clientInfo;
    socklen_t addr_len = sizeof(addr);
    char ip[20];
    // printf("BLOCK IP: %s",blockip);
    getpeername(*client, (struct sockaddr *)&addr, &addr_len);
    memcpy(&clientInfo, &addr, addr_len);
    memcpy(ip, inet_ntoa(clientInfo.sin_addr), sizeof(ip));
    ip[20] = '\0';
    for(int i=0; i<30;i++){
        if(strlen(blockList[i].ip)!=0 && strcmp(blockList[i].ip,ip)==0){
            for(int j=0;j<30;j++){
                if(strlen(blockList[i].block_list[j])==0){
                    strcpy(blockList[i].block_list[j],blockip);
                    done = 1;
                    break;
                }
            }
            break;
        }
    }
    if(done == 1)
        cse4589_print_and_log("[%s:SUCCESS]\n","BLOCK");
    else if(done == 0)
        cse4589_print_and_log("[%s:ERROR]\n","BLOCK");
    cse4589_print_and_log("[%s:END]\n","BLOCK");
    
}

void handleUnblockClient(int *client,char *unblockip){
    int done = 0;
    struct sockaddr_in addr, clientInfo;
    socklen_t addr_len = sizeof(addr);
    char ip[20];
    printf("BLOCK IP: %s",unblockip);
    getpeername(*client, (struct sockaddr *)&addr, &addr_len);
    memcpy(&clientInfo, &addr, addr_len);
    memcpy(ip, inet_ntoa(clientInfo.sin_addr), sizeof(ip));
    ip[20] = '\0';
    for(int i=0; i<30;i++){
        if(strlen(blockList[i].ip)!=0 && strcmp(blockList[i].ip,ip)==0){
            for(int j=0;j<30;j++){
                if(strcmp(blockList[i].block_list[j],unblockip)==0){
                    strcpy(blockList[i].block_list[j],"");
                    done = 1;
                    break;
                }
            }
            break;
        }
    }
    if(done == 1)
        cse4589_print_and_log("[%s:SUCCESS]\n","UNBLOCK");
    else if(done == 0)
        cse4589_print_and_log("[%s:ERROR]\n","UNBLOCK");
    cse4589_print_and_log("[%s:END]\n","BLOCK");
    
}

int listBlocked(char *ip){
    struct sockaddr_in sa;
    int result = inet_pton(AF_INET, ip, &(sa.sin_addr));
    printf("Result: %d\n",result);
    if(result <= 0){
        cse4589_print_and_log("[%s:ERROR]\n", "BLOCKED");
        return 1;
    }
    int count = 0;
    cse4589_print_and_log("[%s:SUCCESS]\n", "BLOCKED");
    for(int i=0; i<30;i++){
        if(strlen(blockList[i].ip)!=0 && strcmp(blockList[i].ip,ip)==0){
            for(int j=0;j<30;j++){
                if(strlen(blockList[i].block_list[j])!=0){
                    listBlockedClients(client_connections,blockList[i].block_list[j],&count);
                }
            }
        }
    }
}

struct clientStats clientStatsList[30] = {0};
struct messageQueue clientQueue[30] = {0};
void handleSendData(int *client, char *msg);

void initClientQueue(int *client)
{
    int client_found = 0;
    struct sockaddr_in addr, clientInfo;
    socklen_t addr_len = sizeof(addr);
    char ip[20];
    getpeername(*client, (struct sockaddr *)&addr, &addr_len);
    memcpy(&clientInfo, &addr, addr_len);
    memcpy(ip, inet_ntoa(clientInfo.sin_addr), sizeof(ip));
    ip[20] = '\0';
    for (int i = 0; i < 30; i++)
    {
        if (strlen(clientQueue[i].ip) != 0 && strcmp(clientQueue[i].ip, ip) == 0)
        {
            // printf("Found client\n");
            client_found = 1;
            break;
        }
    }
    if (client_found == 0)
    {
        for (int i = 0; i < 30; i++)
        {
            if (strlen(clientQueue[i].ip) == 0)
            {
                strcpy(clientQueue[i].ip, ip);
                clientQueue[i].front = -1;
                clientQueue[i].rear = -1;
                break;
            }
        }
    }
}

void enqueue(struct messageQueue *queue, char *msg)
{
    printf("Enqueing message for ip: %s\n", queue->ip);
    if (queue->rear == MAX_SIZE - 1)
        printf("\nQueue is Full!!");
    else
    {
        if (queue->front == -1)
            queue->front = 0;
        queue->rear++;
        strcpy(queue->messages[queue->rear], msg);
        // printf("\nInserted -> %d", value);
    }
}

void dequeue(int *client, struct messageQueue *queue)
{
    int sendclient;
    if (queue->front == -1)
        printf("\nQueue is Empty!!");
    else
    {
        printf("Sending data..\n");
        char *data1 = queue->messages[queue->front];
        unsigned char *ip = strsep(&data1, " ");
        trim_newline(ip);
        trim_newline(data1);
        unsigned char *data = queue->messages[queue->front];
        unsigned char *prepend = (char *)"SEND ";
        unsigned char *separator = (char *)"-";
        unsigned char dataToSend[sizeof(prepend) + sizeof(ip) + sizeof(separator) + sizeof(queue->messages[queue->front]) + 5];

        // printf("%s,%s,%d\n",ip,data1,sizeof(dataToSend));

        strcpy(dataToSend,prepend);
        strcat(dataToSend,ip);
        strcat(dataToSend,separator);
        strcat(dataToSend,data1);
        // printf("%d\n",*client);
        if(send(*client,dataToSend, sizeof(dataToSend),0)<0){
            perror("Error to send data");
        }
        // sendMessage(client,queue->messages[queue->front]);
        // strcpy(queue->messages[queue->front],"");
        // printf("After: %s\n",dataToSend);
        queue->front++;
        if (queue->front > queue->rear)
            queue->front = queue->rear = -1;
        // handleSendData(client,msg);
    }
}

void updateClientQueue(char *ip,char * msg){
    int done = 0;
    for(int i=0;i<30;i++){
        if(strcmp(ip,clientQueue[i].ip)==0){
            enqueue(&clientQueue[i],msg);
            done = 1;
            break;
        }
    }
    if(done == 0){
        cse4589_print_and_log("[%s:ERROR]\n","RELAYED");
        cse4589_print_and_log("[%s:END]\n","RELAYED");
    }
}

void updateClientStats(int *client, int sent, int received)
{
    struct sockaddr_in addr, clientInfo;
    socklen_t addr_len = sizeof(addr);
    char ip[20];
    getpeername(*client, (struct sockaddr *)&addr, &addr_len);
    memcpy(&clientInfo, &addr, addr_len);
    memcpy(ip, inet_ntoa(clientInfo.sin_addr), sizeof(ip));
    ip[20] = '\0';
    int clientFound = 0;
    for (int i = 0; i < 30; i++)
    {
        if (strcmp(ip, clientStatsList[i].ip) == 0)
        {
            // printf("Found Client\n");
            if (sent == 1)
            {
                clientStatsList[i].message_sent_count += 1;
            }
            if (received == 1)
            {
                clientStatsList[i].message_receive_count += 1;
            }
            clientFound = 1;
        }
    }
    if (clientFound == 0)
    {
        // puts("Did not find client");
        for (int i = 0; i < 30; i++)
        {
            if (strlen(clientStatsList[i].ip) == 0)
            {
                // puts("Adding client here");
                strcpy(clientStatsList[i].ip, ip);
                clientStatsList[i].port = ntohs(clientInfo.sin_port);
                clientStatsList[i].message_sent_count = 0;
                clientStatsList[i].message_receive_count = 0;
                break;
            }
        }
    }
}

void showStats()
{
    for (int i = 0; i < 30; i++)
    {
        struct sockaddr_in addr, clientInfo;
        socklen_t addr_len = sizeof(addr);
        char ip[20];
        char host[256];
        if(strcmp(clientStatsList[i].ip,"128.205.36.46")==0){
                strcpy(host,"stones.cse.buffalo.edu");
            }
            else if(strcmp(clientStatsList[i].ip,"128.205.36.35")==0){
                strcpy(host,"embankment.cse.buffalo.edu");
            }
            else if(strcmp(clientStatsList[i].ip,"128.205.36.33")==0){
                strcpy(host,"highgate.cse.buffalo.edu");
            }
            else if(strcmp(clientStatsList[i].ip,"128.205.36.34")==0){
                strcpy(host,"euston.cse.buffalo.edu");
            }
            else if(strcmp(clientStatsList[i].ip,"128.205.36.8")==0){
                strcpy(host,"timberlake.cse.buffalo.edu");
            }
            else if(strcmp(clientStatsList[i].ip,"128.205.36.36")==0){
                strcpy(host,"underground.cse.buffalo.edu");
            }
            else {
                strcpy(host,"docker");
            }
        if (client_connections[i] != 0)
        {
            getpeername(client_connections[i], (struct sockaddr *)&addr, &addr_len);
            memcpy(&clientInfo, &addr, addr_len);
            memcpy(ip, inet_ntoa(clientInfo.sin_addr), sizeof(ip));
            if (strcmp(ip, clientStatsList[i].ip) == 0)
            {
                cse4589_print_and_log("%-5d%-35s%-8d%-8d%-8s\n", (i + 1), host,
                                      clientStatsList[i].message_sent_count, clientStatsList[i].message_receive_count, "logged-in");
                // printf("Client IP: %s, Messages Sent: %d, Messages Received: %d\n",clientStatsList[i].ip,
                // clientStatsList[i].message_sent_count,clientStatsList[i].message_receive_count);
            }
        }
        else if (strlen(clientStatsList[i].ip) != 0)
        {
            cse4589_print_and_log("%-5d%-35s%-8d%-8d%-8s\n", (i + 1), host,
                                  clientStatsList[i].message_sent_count, clientStatsList[i].message_receive_count, "logged-out");
        }
    }
}

void parse_user_input(char *s)
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
        getPort(&server_address);
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
        cse4589_print_and_log("[%s:SUCCESS]\n", "LIST");
        listClients(client_connections);
        cse4589_print_and_log("[%s:END]\n", "LIST");
    }
    else if (strcmp(token, "STATISTICS") == 0)
    {
        cse4589_print_and_log("[%s:SUCCESS]\n", "STATISTICS");
        showStats();
        cse4589_print_and_log("[%s:END]\n", "STATISTICS");
    }

    else if (strcmp(token, "BLOCKED") == 0)
    {
        // cse4589_print_and_log("[%s:SUCCESS]\n", "BLOCKED");
        listBlocked(s);
        cse4589_print_and_log("[%s:END]\n", "BLOCKED");
    }

    else
    {
        printf("Invalid Command\n");
    }
}

void handleRefresh(int *client)
{
    sendClientList(client, client_connections);
}

void handleSendData(int *client, char *msg)
{
    int data_sent = 0;
    int blocked = 0;
    // printf("%s\n",msg);
    char *token; // who to send
    token = strsep(&msg, "-");
    trim_newline(token);
    trim_newline(msg);
    struct clientsBlocked clientBLockList;
    for (int i = 0; i < 30; i++)
    {
        struct sockaddr_in addr, clientInfo;
        socklen_t addr_len = sizeof(addr);
        char ip[20];
        if (client_connections[i] != 0)
        {
            getpeername(client_connections[i], (struct sockaddr *)&addr, &addr_len);
            memcpy(&clientInfo, &addr, addr_len);
            memcpy(ip, inet_ntoa(clientInfo.sin_addr), sizeof(ip));
            ip[20] = '\0';
            if (strcmp(ip, token) == 0)
            {   
                struct sockaddr_in senderAddr, senderInfo;
                socklen_t senderAddr_len = sizeof(senderAddr);
                char senderIp[20]; // who sent
                unsigned char *messageData = msg;
                getpeername(*client, (struct sockaddr *)&senderAddr, &senderAddr_len);
                memcpy(&senderInfo, &senderAddr, senderAddr_len);
                memcpy(senderIp, inet_ntoa(senderInfo.sin_addr), sizeof(senderIp));
                senderIp[20] = '\0';
                // printf("Sender: %s, Receiver: %s\n",senderIp,ip);
                for(int j=0;j<30;j++){
                    if(strlen(blockList[j].ip)!=0 && strcmp(blockList[j].ip,ip)==0){
                        // printf("Found client\n");
                        for(int k=0;k<30;k++){
                            if(strlen(blockList[j].block_list[k])!=0 && strcmp(blockList[j].block_list[k],senderIp)==0)
                                // printf("Am I blocked ?\n");
                                blocked = 1;
                        }
                    }
                }
                if(blocked == 0){
                    unsigned char *separator = (char *)" ";
                    unsigned char data[sizeof(senderIp) + sizeof(separator) + 2048];
                    // printf("%d\n",sizeof(data));
                    strcpy(data, senderIp);
                    // printf("%s,%d\n",data,strlen(data));
                    memcpy(data + strlen(senderIp), separator, sizeof(separator) + sizeof(senderIp));
                    // printf("%s,%d\n",data,strlen(data));
                    // memcpy(data + strlen(senderIp) + strlen(separator), messageData, sizeof(separator) + sizeof(senderIp) + sizeof(messageData));
                    strcat(data,messageData);
                    // printf("%s,%d\n",data,strlen(data));
                    // printf("%s,%d\n",messageData,strlen(messageData));
                    int status = sendMessage(&client_connections[i],data);
                    if(status == 0){
                        cse4589_print_and_log("[%s:SUCCESS]\n","RELAYED");
                        cse4589_print_and_log("msg from:%s, to:%s\n[msg]:%s\n", senderIp, ip, msg);
                    }
                    else if(status == 1)
                        cse4589_print_and_log("[%s:ERROR]\n","RELAYED");
                    cse4589_print_and_log("[%s:END]\n","RELAYED");
                    updateClientStats(client,1,0);
                    updateClientStats(&client_connections[i],0,1);
                    data_sent = 1;
                }
            }
        }
    }
    if (data_sent == 0 && blocked==0)
    {
        struct sockaddr_in senderAddr, senderInfo;
        socklen_t senderAddr_len = sizeof(senderAddr);
        char senderIp[20];
        unsigned char *messageData = msg;
        getpeername(*client, (struct sockaddr *)&senderAddr, &senderAddr_len);
        memcpy(&senderInfo, &senderAddr, senderAddr_len);
        memcpy(senderIp, inet_ntoa(senderInfo.sin_addr), sizeof(senderIp));
        senderIp[20] = '\0';
        unsigned char *separator = (char *)" ";
        // unsigned char * separator1 = (char *)"-";
        unsigned char data[sizeof(senderIp) + sizeof(separator) + sizeof(msg)];
        // printf("%d\n",sizeof(data));
        strcpy(data, senderIp); // senderIP
        strcat(data, separator);
        strcat(data, messageData);
        updateClientQueue(token, data);
    }
}

void sendQueuedMessages(int *client)
{
    struct sockaddr_in addr, clientInfo;
    socklen_t addr_len = sizeof(addr);
    char ip[20];
    // printf("Sending queued messages...\n");
    getpeername(*client, (struct sockaddr *)&addr, &addr_len);
    memcpy(&clientInfo, &addr, addr_len);
    memcpy(ip, inet_ntoa(clientInfo.sin_addr), sizeof(ip));
    ip[20] = '\0';
    for (int i = 0; i < 30; i++)
    {
        if (strcmp(ip, clientQueue[i].ip) == 0 && clientQueue[i].rear != -1)
        {
            while (clientQueue[i].rear != -1)
            {
                dequeue(client, &clientQueue[i]);
            }
        }
    }
}

void parse_client_data(int *client, char *s)
{
    char *token;
    // printf("%s\n",s);
    token = strsep(&s, " ");
    trim_newline(token);
    if (strcmp(token, "REFRESH") == 0)
    {
        handleRefresh(client);
    }
    else if (strcmp(token, "SEND") == 0)
    {
        handleSendData(client, s);
    }
    else if (strcmp(token, "BROADCAST") == 0)
    {
        handleBroadcast(client, s);
    }
    else if (strcmp(token, "BLOCK") == 0)
    {
        handleBlockClient(client, s);
    }
    else if (strcmp(token, "UNBLOCK") == 0)
    {
        handleUnblockClient(client, s);
    }
}

void start_server(int port)
{

    struct sockaddr_storage client_address;

    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(port);
    server_address.sin_addr.s_addr = INADDR_ANY;

    // for (int i = 0; i < total_clients; i++)
    // {
    //     client_connections[i] = 0;
    // }
    // printf("Inside start_server()");
    if ((server_socket = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
        printf("Server: Error");
        exit(EXIT_FAILURE);
    }

    bind(server_socket, (struct sockaddr *)&server_address, sizeof(server_address));
    listen(server_socket, 5);

    addrlen = sizeof(server_address);
    puts("Waiting for connections ...");

    initClientList(client_connections);

    while (1)
    {
        FD_ZERO(&read_descriptors);

        // add master socket to set
        FD_SET(server_socket, &read_descriptors);
        FD_SET(STDIN_FILENO, &read_descriptors);
        max_socket_descriptors = server_socket;
        fflush(stdin);
        // puts(">");

        for (int i = 0; i < total_clients; i++)
        {
            // socket descriptor
            sd = client_connections[i];

            // if valid socket descriptor then add to read list
            if (sd > 0)
                FD_SET(sd, &read_descriptors);

            // highest file descriptor number, need it for the select function
            if (sd > max_socket_descriptors)
                max_socket_descriptors = sd;
        }

        select(max_socket_descriptors + 1, &read_descriptors, NULL, NULL, NULL);

        if (FD_ISSET(server_socket, &read_descriptors))
        {

            if ((client_socket = accept(server_socket,
                                        (struct sockaddr *)&client_address, (socklen_t *)&addrlen)) < 0)
            {
                perror("accept");
                exit(EXIT_FAILURE);
            }
            addClient(&client_socket, client_connections);
            initClientQueue(&client_socket);
            updateClientStats(&client_socket, 0, 0);
            // for (int i = 0; i < total_clients; i++)
            // {
            //     //if position is empty
            //     if( client_connections[i] == 0 )
            //     {
            //         client_connections[i] = client_socket;
            //         printf("Adding to list of sockets as %d\n" , i);
            //         unsigned char data[sizeof(clientList)];
            //         // data = (unsigned char)malloc(sizeof(clientList[0]));
            //         memcpy(data,clientList, sizeof(clientList));
            //         // printf("%u\n",data);
            //         // printf("hello\n");
            //         send(client_socket,data,sizeof(data),0);
            //         break;
            //     }
            // }
            sendClientList(&client_socket, client_connections);
            // unsigned char data[sizeof(client_connections)];
            // memcpy(data,client_connections, sizeof(client_connections));
            // send(client_socket,data,sizeof(data),0);
            // char buf[1024];
            // memset(buf, 0, sizeof(buf));
            // int lastBit;
            initBlockList(&client_socket);
            sendQueuedMessages(&client_socket);

            // lastBit = recv(server_socket, buf, sizeof(buf), 0);
            // if (lastBit > 0 && lastBit < 1024)
            // {
            //     buf[lastBit] = '\0';
            // }
            // else
            // {
            //     close(server_socket);
            // }
        }
        else if (FD_ISSET(STDIN_FILENO, &read_descriptors))
        {
            char msg[8046];
            memset(msg, 0, sizeof(msg));
            fgets(msg, 8046, stdin);
            trim_newline(msg);
            parse_user_input(msg);
        }
        for (int i = 0; i < 30; i++)
        {
            sd = client_connections[i];

            if (FD_ISSET(sd, &read_descriptors) && sd != 0)
            {
                // Check if it was for closing , and also read the
                // incoming message
                if ((valread = read(sd, buf, 8046)) == 0)
                {
                    // Somebody disconnected , get his details and print
                    getpeername(sd, (struct sockaddr *)&client_address,
                                (socklen_t *)&addrlen);
                    // printf("Host disconnected , ip %s , port %d \n" ,
                    //     inet_ntoa(client_address.sin_addr) , ntohs(((struct sockaddr* )client_address).sin_port));

                    // Close the socket and mark as 0 in list for reuse
                    close(sd);
                    // client_connections[i] = 0;
                    removeClient(&client_connections[i], client_connections);
                }
                else
                {
                    // set the string terminating NULL byte on the end
                    // of the data read
                    buf[valread + 1] = '\0';
                    parse_client_data(&sd, buf);
                }
            }
        }
    }
}

void handleBroadcast(int *client, char *msg)
{
    // char *token;
    // token = strsep(&msg, "-");
    // trim_newline(token);
    trim_newline(msg);
    for (int i = 0; i < 30; i++)
    {
        struct sockaddr_in addr, clientInfo;
        socklen_t addr_len = sizeof(addr);
        char ip[20];
        if (client_connections[i] != 0 && client_connections[i] != *client)
        {
            getpeername(client_connections[i], (struct sockaddr *)&addr, &addr_len);
            memcpy(&clientInfo, &addr, addr_len);
            memcpy(ip, inet_ntoa(clientInfo.sin_addr), sizeof(ip));
            ip[20] = '\0';
            struct sockaddr_in senderAddr, senderInfo;
            socklen_t senderAddr_len = sizeof(senderAddr);
            char senderIp[20];
            unsigned char *messageData = msg;
            getpeername(*client, (struct sockaddr *)&senderAddr, &senderAddr_len);
            memcpy(&senderInfo, &senderAddr, senderAddr_len);
            memcpy(senderIp, inet_ntoa(senderInfo.sin_addr), sizeof(ip));
            senderIp[20] = '\0';
            unsigned char *separator = (char *)" ";
            unsigned char data[sizeof(senderIp) + sizeof(separator) + 2048];
            // printf("%d\n", sizeof(data));
            strcpy(data, senderIp);
            // printf("%s,%d\n", data, strlen(data));
            memcpy(data + strlen(senderIp), separator, sizeof(separator) + sizeof(senderIp));
            // printf("%s,%d\n", data, strlen(data));
            // memcpy(data + strlen(senderIp) + strlen(separator), messageData, sizeof(separator) + sizeof(senderIp) + sizeof(messageData));
            strcat(data,messageData);
            // printf("%s,%d\n", data, strlen(data));
            // printf("%s,%d\n", messageData, strlen(messageData));
            cse4589_print_and_log("[%s:SUCCESS]\n","RELAYED");
            cse4589_print_and_log("msg from:%s, to:%s\n[msg]:%s\n", senderIp, "255.255.255.255", msg);
            cse4589_print_and_log("[%s:END]\n","RELAYED");
            sendMessage(&client_connections[i], data);
        }
    }
}