#ifndef __NESCAFE_H
#define __NESCAFE_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <signal.h>

#define BUFFER_SIZE 1024
#define MAX_TTL 64
#define ICMP_ECHO_REQUEST 0
#define ICMP_ECHO_REPLY 0
#define SO_NOSIGPIPE 0x1022

typedef struct{
	unsigned char ttl;
	unsigned char type;
	unsigned short id;
	unsigned short seq;
	unsigned long timestamp;
} icmp_packet_t;

void ping(char *hostname);
void send_packet(int sockfd, int sock, struct sockaddr_in *dest_addr, char *buffer, int ttl);
void receive_packet(int sockfd, int sock, struct sockaddr_in *src_addr, char *buffer, int ttl);
unsigned short calculate_checksum(char *buffer, int len);

#define NESCAFE_SUCCESS 0
#define NESCAFE_ERROR_SOCKET 2
#define NESCAFE_ERROR_SEND -2
#define NESCAFE_ERROR_RECV -3

#endif // __NESCAFE_H
