/* nescafe - curl-like transfer a IP

   nescafe.c

   written by kernelfucker
   
   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>. */

#include "nescafe.h"

void send_icmp_packet(int sockfd, struct sockaddr *dest_addr, socklen_t dest_len, icmp_packet_t *pkt){
	struct icmphdr icmp_hdr;
	icmp_hdr.type = ICMP_ECHO_REQUEST;
	icmp_hdr.code = 0;
	icmp_hdr.un.echo.id = pkt->id;
	icmp_hdr.un.echo.sequence = pkt->seq;
	icmp_hdr.checksum = 0;
	
	char buffer[BUFFER_SIZE];
	memcpy(buffer, &icmp_hdr, sizeof(icmp_hdr));
	memcpy(buffer + sizeof(icmp_hdr), &pkt->timestamp, sizeof(pkt->timestamp));

	icmp_hdr.checksum = calculate_checksum(buffer, sizeof(icmp_hdr) + sizeof(pkt->timestamp));
	memcpy(buffer, &icmp_hdr, sizeof(icmp_hdr));
	
		if (sendto(sockfd, buffer, sizeof(icmp_hdr) + sizeof(pkt->timestamp), 0, (struct sockaddr *)&dest_addr, dest_len) < 0) {
		perror("sendto");
		exit(NESCAFE_ERROR_SEND);
	}
}

void receive_icmp_packet(int sockfd, struct sockaddr *src_addr, socklen_t *src_len, icmp_packet_t *pkt){
	char buffer[BUFFER_SIZE];
	socklen_t len = *src_len;
	if (recvfrom(sockfd, buffer, BUFFER_SIZE, 0, src_addr, &len) < 0){
		perror("recvfrom");
		exit(NESCAFE_ERROR_RECV);
	}
	
	struct icmphdr *icmp_hdr = (struct icmphdr *) buffer;
	if (icmp_hdr->type == ICMP_ECHO_REPLY){
		pkt->id = icmp_hdr->un.echo.id;
		pkt->seq = icmp_hdr->un.echo.sequence;
		pkt->timestamp = *(unsigned long *) (buffer + sizeof(struct icmphdr));
	}
}

unsigned short calculate_checksum(char *buffer, int len){
	unsigned long sum = 0;
	for (int i = 0; i < len; i += 2){
		unsigned short word = *(unsigned short *) (buffer + i);
		sum += word;
	}

	while (sum > 0xFFFF){
		sum = (sum >> 16) + (sum & 0xFFFF);
	}

	return ~sum;
}

int create_socket(){
	signal(SIGPIPE, SIG_IGN);
	int sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0){
		perror("socket");
		exit(NESCAFE_ERROR_SOCKET);
	}
	int opt = 1;
	setsockopt(sockfd, SOL_SOCKET, SO_NOSIGPIPE, &opt, sizeof(opt));

	return sockfd;
}

int create_socket_v6(){
	signal(SIGPIPE, SIG_IGN);
	int sockfd = socket(AF_INET6, SOCK_STREAM, 0);	
	if (sockfd < 0){
		perror("socket");
		exit(NESCAFE_ERROR_SOCKET);
	}
	int opt = 0;
	setsockopt(sockfd, IPPROTO_IPV6, IPV6_V6ONLY, &opt, sizeof(opt));
	opt = 1;
	setsockopt(sockfd, SOL_SOCKET, SO_NOSIGPIPE, &opt, sizeof(opt));

	return sockfd;
}

void set_ttl(int sockfd, int ttl){
	if (setsockopt(sockfd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) < 0){
		perror("setsockopt");
		exit(NESCAFE_ERROR_SOCKET);
	}
}

int main(int argc, char *argv[]){
	if (argc != 2){
		printf("Usage: %s <destination_ip>\n", argv[0]);
		return NESCAFE_ERROR_SOCKET;
	}
	
    struct sockaddr_in serv_addr;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(80);

    if (inet_pton(AF_INET, argv[1], &serv_addr.sin_addr) <= 0) {
        printf("Invalid hostname or IP address\n");
        return NESCAFE_ERROR_SOCKET;
    }

    int sockfd = create_socket();

    if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("connect");
        return NESCAFE_ERROR_SOCKET;
    }

    char *message = "GET / HTTP/1.1\r\nHost: \r\n\r\n\r\n";
    send(sockfd, message, strlen(message), 0);

    char buffer[1024];
    read(sockfd, buffer, 1024);
    printf("%s", buffer);

    close(sockfd);
    return NESCAFE_ERROR_SOCKET;
}
