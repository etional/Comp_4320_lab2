/*
** server.c -- a stream socket server demo
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <net/if.h>

//#define PORT "10085"  // the port users will be connecting to
#define MAXBUFLEN 100
#define BACKLOG 10	 // how many pending connections queue will hold
#define TRUE 1
#define FALSE 0

typedef signed char byte;
typedef unsigned int boolean;

//struct for Master
typedef struct{
	byte gid;
	byte rid;
	byte nextRID;
	char nextSlaveIP[INET_ADDRSTRLEN];
	long key;
} master;

//struct for Slave
typedef struct {
	byte gid;
	byte rid;
	char nextIP[INET_ADDRSTRLEN];
	long magic;
	boolean valid;
} slave;

void sigchld_handler(int s)
{
	// waitpid() might overwrite errno, so we save and restore it:
	int saved_errno = errno;

	while(waitpid(-1, NULL, WNOHANG) > 0);

	errno = saved_errno;
}


// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
	if (sa->sa_family == AF_INET) {
		return &(((struct sockaddr_in*)sa)->sin_addr);
	}

	return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

//check validity of join request
void checkValid(master ma, slave *sla) {
	if (ma.gid != sla->gid || ma.key != sla->magic) {
		sla->valid = FALSE;
	}
	else {
		sla->valid = TRUE;
	}
}

//update values of Master and values of packet to send to Slavee
void connectSlave(master *ma, slave *sl, char *addr) {
	sl->rid = ma->nextRID;
	strcpy(sl->nextIP, ma->nextSlaveIP);
	ma->nextRID++;
	strcpy(ma->nextSlaveIP, addr);
}

int main(int argc, char *argv[])
{
	int sockfd, new_fd;  // listen on sock_fd, new connection on new_fd
	struct addrinfo hints, *servinfo, *p;
	struct hostent* hostInfo;
	struct in_addr hostIP;
	struct sockaddr_storage their_addr; // connector's address information
	socklen_t sin_size;
	struct sigaction sa;
	int yes=1;
	char s[INET_ADDRSTRLEN];
	char host[1024];
	host[1023] = '\0';
	int numbyte;
	char buf[MAXBUFLEN];
	int rv;

	master m;
	slave sl;
	int n1, n2, n3, n4;
	int port;
	char *endptr;

	//initializing master
	m.rid = 0;
	port = strtol(argv[1], &endptr, 10);
	port = ((port - 10010) / 5);
	m.gid = (char) port;
	m.nextRID = 1;
	m.key = strtol("4A6F7921", NULL, 16);

	gethostname(host, 1023);
	printf("\nHostname: %s\n", host);
	hostInfo = gethostbyname(host);
	hostIP = *(struct in_addr *)hostInfo->h_addr;
	strcpy(m.nextSlaveIP, inet_ntoa(hostIP));
	printf("IP: %s\n\n", m.nextSlaveIP);

	sl.valid = FALSE;

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE; // use my IP

	if (argc != 2) {
		fprintf(stderr, "usage: Master MasterPort#\n");
		exit(1);
	}

	if ((rv = getaddrinfo(NULL, argv[1], &hints, &servinfo)) != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
		return 1;
	}

	// loop through all the results and bind to the first we can
	for(p = servinfo; p != NULL; p = p->ai_next) {
		if ((sockfd = socket(p->ai_family, p->ai_socktype,
				p->ai_protocol)) == -1) {
			perror("server: socket");
			continue;
		}

		if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes,
				sizeof(int)) == -1) {
			perror("setsockopt");
			exit(1);
		}

		if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
			close(sockfd);
			perror("server: bind");
			continue;
		}
		break;
	}

	freeaddrinfo(servinfo); // all done with this structure

	if (p == NULL)  {
		fprintf(stderr, "server: failed to bind\n");
		exit(1);
	}

	if (listen(sockfd, BACKLOG) == -1) {
		perror("listen");
		exit(1);
	}

	sa.sa_handler = sigchld_handler; // reap all dead processes
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART;
	if (sigaction(SIGCHLD, &sa, NULL) == -1) {
		perror("sigaction");
		exit(1);
	}

	printf("server: waiting for connections...\n");

	while(1) {  // main accept() loop
		printf("Listenning...\n\n");
		sin_size = sizeof their_addr;
		new_fd = accept(sockfd, (struct sockaddr *)&their_addr, &sin_size);
		if (new_fd == -1) {
			perror("accept");
			continue;
		}

		inet_ntop(their_addr.ss_family,
			get_in_addr((struct sockaddr *)&their_addr),
			s, sizeof s);
		printf("server: got connection from %s\n", s);

		if ((numbyte = read(new_fd, buf, MAXBUFLEN)) == -1) {
			perror("read");
			exit(1);
		}

		printf("server: got packet from %s\n", s);
		printf("server: packet is %d bytes long\n", numbyte);
		printf("server: packet contains: ");
		int i = 0;
		for (i = 0; i < numbyte; i++) {
			printf("%02x ", buf[i] & 0xFF);
		}

		if (numbyte != 5) {
			printf("\nReceived Invalid packet: Not received 5 bytes packet\n");
			printf("Disconnect\n");
			close(new_fd);
			continue;
		}

		printf("\n");
		printf("GID: %d\n", buf[0]);
		printf("MAGIC KEY: %lx\n\n", (long)(buf[1] << 24 | buf[2] << 16 | buf[3] << 8 | buf[4]));

		printf("Server contains:\n");
		printf("\tGID: %d\n", m.gid);
		printf("\tRID: %d\n", m.rid);
		printf("\tNext RID: %d\n", m.nextRID);
		printf("\tNext Slave IP: %s\n", m.nextSlaveIP);
		printf("\tKEY: %lx\n\n", m.key);

		sl.gid = buf[0];
		sl.magic = (long)(buf[1] << 24 | buf[2] << 16 | buf[3] << 8 | buf[4]);

		printf("server: checking validity\n");
		checkValid(m, &sl);

		if (sl.valid == TRUE) {
			printf("Packet is valid\n\n");
			printf("server: connecting a new slave...\n");
			connectSlave(&m, &sl, s);
			printf("New slave is connected\n\n");
		}
		else {
			buf[0] = -1;
			buf[1] = 1;
			buf[2] = 2;
			buf[3] = 3;
			buf[4] = 4;
			buf[5] = 5;
			buf[6] = 6;
			buf[7] = 7;
			buf[8] = 8;
			buf[9] = 9;
			printf("Received Invalid packet\n");
			if (send(new_fd, buf, 10, 0) == -1) 
				perror("send");
			printf("Disconnect\n");
			close(new_fd);
			continue;
		}

		printf("server: creating packet...\n");
		buf[0] = sl.gid;
		buf[1] = m.key >> 24 & 0xFF;
		buf[2] = m.key >> 16 & 0xFF;
		buf[3] = m.key >> 8 & 0xFF;
		buf[4] = m.key & 0xFF;
		buf[5] = sl.rid;
		sscanf(sl.nextIP, "%d.%d.%d.%d", &n1, &n2, &n3, &n4);
		buf[6] = n1 & 0xFF;
		buf[7] = n2 & 0xFF;
		buf[8] = n3 & 0xFF;
		buf[9] = n4 & 0xFF;

		printf("Packet contains: \n");
		printf("GID: %d\n", sl.gid);
		printf("MAGIC KEY: %lx\n", sl.magic);
		printf("RID: %d\n", sl.rid);
		printf("NEXTSLAVEIP: %s\n", sl.nextIP);
		printf("Full packet in hex: ");
		for (i = 0; i < 10; i++) {
			printf("%02x ", buf[i] & 0xFF);
		}
		printf("\n\n");

		if (!fork()) { // this is the child process
			close(sockfd); // child doesn't need the listener
			if (send(new_fd, buf, 10, 0) == -1)  
				perror("send");
			close(new_fd);
			exit(0);
		}
		close(new_fd);  // parent doesn't need this
		printf("server: sent packet\n\n");

		printf("Server status after connection:\n");
		printf("Server contains:\n");
		printf("\tGID: %d\n", m.gid);
		printf("\tRID: %d\n", m.rid);
		printf("\tNext RID: %d\n", m.nextRID);
		printf("\tNext Slave IP: %s\n", m.nextSlaveIP);
		printf("\tKEY: %lx\n\n", m.key);
	}

	return 0;
}

