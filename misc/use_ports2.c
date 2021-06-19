#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <string.h>

#define MAX_PORT 65536
#define LOW_PORT 512
#define HIGH_PORT 1023

int make_socket(unsigned short port, int use_tcp) {
	int sock;
	int tmp;
//	struct protoent *protoent;
	struct sockaddr_in name;
	int sock_proto;
	int sock_type;

	if (use_tcp) {
		sock_proto = IPPROTO_TCP;
		sock_type = SOCK_STREAM;
	} else {
		sock_proto = IPPROTO_UDP;
		sock_type = SOCK_DGRAM;
	}

	name.sin_family = AF_INET;
	name.sin_port = htons(port);
/*
	struct hostent hostinfo *hostinfo = gethostbyname("0.0.0.0");
	if (hostinfo == NULL) {
		printf("argh!  %m\n");
		exit(EXIT_FAILURE);
	}
*/

//	name.sin_addr = *(struct in_addr *)hostinfo->h_addr;
//	name.sin_addr.s_addr = htonl(INADDR_ANY);
	name.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

//	if ((sock = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
	if ((sock = socket(PF_INET, sock_type, sock_proto)) < 0) {
		printf("error with socket: %m\n");
		return -1;
	}

	tmp = 1;
	setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char *)&tmp, sizeof(tmp));

	/* do or don't enable tcp keepalive */
//	tmp = 1;
//	setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, (char *)&tmp, sizeof(tmp));

	if ((bind(sock, (struct sockaddr *)&name, sizeof(name))) < 0) {
		printf("error with bind (%s %d): %m\n", use_tcp ? "tcp" : "udp", port);
		return -1;
	}

	if (use_tcp) {
//		protoent = getprotobyname("tcp");
		/* screw error checking */
//		tmp = 1;
//		setsockopt(sock, protoent->p_proto, TCP_NODELAY, (char *)&tmp, sizeof(tmp));
	}
	return sock;
}
void mark_to_open(int *to_open, int port) {
	to_open[port] = 1;
}
void fill_open_range(int *to_open, int low, int high) {
	int i, range = high - low + 1;

	for (i = 0 ; i < range ; i++)
		mark_to_open(to_open, i + low);
}

int use_ports(int *to_open, int port_count) {
	int sock, *socks[2], open_socks[2] = { 0, 0 };
	int i, udp_tcp, port;

/*
	for (i = 0 ; i < MAX_PORT ; i++) {
		if (to_open[i])
			printf("would open port %d\n", i);
	}
	return 0;
*/

	socks[0] = malloc(port_count * sizeof(int));
	socks[1] = malloc(port_count * sizeof(int));

	for (i = 0 ; i < MAX_PORT ; i++) {
		if (! to_open[i])
			continue;

		port = i;
		for (udp_tcp = 0 ; udp_tcp <= 1 ; udp_tcp++) {
			if ((sock = make_socket(port, udp_tcp)) < 0) {
				printf("unable to open '%s' port '%d'\n", udp_tcp ? "tcp" : "udp", port);
				continue;
			}
			if (udp_tcp) {
				if ((listen(sock, 1)) < 0) {
					printf("unable to listen on '%s' port '%d': %m\n", udp_tcp ? "tcp" : "udp", port);
					continue;
				}
			}
			socks[udp_tcp][open_socks[udp_tcp]++] = sock;
		}
	}
	if (open_socks[0] > 0 || open_socks[1] > 0) {
		printf("opened %d sockets (%d udp, %d tcp)\n", open_socks[0] + open_socks[1], open_socks[0], open_socks[1]);

		while (42)
			sleep(1);
	} else {
		printf("unable to open any sockets\n");
	}
	return (open_socks[0] + open_socks[1]);
}

int count_to_open(int *to_open) {
	int i, to_open_count = 0;

	for (i = 0 ; i < MAX_PORT ; i++)
		to_open_count += to_open[i];
	return to_open_count;
}

int main(int argc, char *argv[]) {
	int to_open_count = 0;
	int *to_open = NULL;
	struct rlimit current_fd_limit;

	getrlimit(RLIMIT_NOFILE, &current_fd_limit);

	if (current_fd_limit.rlim_cur < 2048) {
		current_fd_limit.rlim_cur = 2048;
		setrlimit(RLIMIT_NOFILE, &current_fd_limit);
	}

	to_open = malloc(MAX_PORT * sizeof(int));
	memset(to_open, 0, MAX_PORT * sizeof(int));


	if (argc == 1) {
		fill_open_range(to_open, LOW_PORT, HIGH_PORT);
	} else {
		int i;
		char *p;

		for (i = 1 ; i < argc ; i++) {
			int low, high = 0;

			low = strtol(argv[i], &p, 10);
			if (low == 0) {
				printf("unable to parse '%s'\n", argv[i]);
				continue;
			}
			if (strlen(p) > 1 && p[0] == '-') { // range
				p++;
				high = strtol(p, NULL, 10);
			}
			if (high < low)
				high = low;
			fill_open_range(to_open, low, high);
		}

	}
	to_open_count = count_to_open(to_open);

	if (to_open_count == 0) {
		printf("no ports to open\n");
		return EXIT_FAILURE;
	}
	if (use_ports(to_open, to_open_count)) {
		while (42)
			sleep(1);
	} else
		return EXIT_FAILURE;

	return EXIT_SUCCESS;
}
