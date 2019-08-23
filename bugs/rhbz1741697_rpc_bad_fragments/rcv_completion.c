#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <netdb.h>
#include <string.h>
#include <time.h>

#define LISTEN_PORT 4242
#define LISTEN_BACKLOG 5
#define BUF_SIZE 1024

/* completion message expected to contain remote timestamp string followed by 'RPC: fragment too large' */
#define TSTAMP_STRING "YYYY-MM-DD HH:MM:SS:NNNNNNNNN ZZZZ"
// now=$(date +"%F %H:%M:%S.%N %4Z") ; echo -n "$now RPC: fragment too large" >/dev/tcp/CLIENT/4242
// 2019-08-22 07:23:21.915416896  CDT

#define COMPLETION_MSG "RPC: fragment too large"

#define ADDR_STR_LEN (INET6_ADDRSTRLEN * 2 + 20)

char *tstamp(void) {
	struct timespec now;
	char time_buffer[32];
	struct tm tm_info;
	char tzbuf[8];
	char *tstamp;

	clock_gettime(CLOCK_REALTIME, &now);

	localtime_r(&now.tv_sec, &tm_info);
	strftime(time_buffer, sizeof(time_buffer), "%F %T", &tm_info);
	strftime(tzbuf, 8, "%4Z", &tm_info);
	asprintf(&tstamp, "%s.%09ld %s", time_buffer, now.tv_nsec, tzbuf);

	return tstamp;
}

#define tstamp_printf(args...) do { \
	char *ts_str = tstamp(); \
	printf("%s: ", ts_str); \
	printf(args); \
	free(ts_str); \
	fflush(stdout); \
} while (0)

#define exit_fail(args...) do { \
	tstamp_printf(args); \
	exit(EXIT_FAILURE); \
} while (0)

int main(int argc, char *argv[]) {
	struct sockaddr_in6 me, peer;
	const int yes_flag = 1;
	int sock_fd, conn_fd;
	socklen_t addr_size;

	if ((sock_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
		exit_fail("error '%m' opening socket");
	if (setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, &yes_flag, sizeof(int)) < 0)
		exit_fail("error '%m' calling setsockopt(SO_REUSEADDR)");
	if (setsockopt(sock_fd, SOL_SOCKET, SO_REUSEPORT, &yes_flag, sizeof(int)) < 0)
		exit_fail("error '%m' calling setsockopt(SO_REUSEPORT)");

	addr_size = sizeof(me);
	memset(&me, 0, addr_size);
	((struct sockaddr_in *)&me)->sin_family = AF_INET;
	((struct sockaddr_in *)&me)->sin_port = htons(LISTEN_PORT);

	if (bind(sock_fd, (struct sockaddr *)&me, addr_size) < 0)
		exit_fail("error '%m' calling bind");
	if (listen(sock_fd, LISTEN_BACKLOG) < 0)
		exit_fail("error '%m' calling listen");

	tstamp_printf("monitoring starting\n");

	while ((conn_fd = accept(sock_fd, (struct sockaddr *)&peer, &addr_size)) >= 0) {
		char addr_str[ADDR_STR_LEN];
		char rcvbuf[BUF_SIZE];
		int str_len = 0;
		int ret;

		getsockname(conn_fd, (struct sockaddr *)&me, &addr_size);
		getpeername(conn_fd, (struct sockaddr *)&peer, &addr_size);

		if (((struct sockaddr *)&peer)->sa_family == AF_INET) {
			struct sockaddr_in *me4 = (struct sockaddr_in *)&me;
			struct sockaddr_in *peer4 = (struct sockaddr_in *)&peer;

			inet_ntop(AF_INET, &peer4->sin_addr, addr_str, ADDR_STR_LEN);
			str_len = strlen(addr_str);
			snprintf(addr_str + str_len, ADDR_STR_LEN - str_len, ":%d => ", ntohs(peer4->sin_port));

			str_len = strlen(addr_str);
			inet_ntop(AF_INET, &me4->sin_addr, addr_str + str_len, ADDR_STR_LEN - str_len);
			str_len = strlen(addr_str);
			snprintf(addr_str + str_len, ADDR_STR_LEN - str_len, ":%d", ntohs(me4->sin_port));
		} else { // AF_INET6
			inet_ntop(AF_INET6, &peer.sin6_addr, addr_str, sizeof(addr_str));
			str_len = strlen(addr_str);
			snprintf(addr_str + str_len, ADDR_STR_LEN - str_len, ":%d => ", ntohs(peer.sin6_port));

			str_len = strlen(addr_str);
			inet_ntop(AF_INET6, &me.sin6_addr, addr_str + str_len, ADDR_STR_LEN - str_len);
			str_len = strlen(addr_str);
			snprintf(addr_str + str_len, ADDR_STR_LEN - str_len, ":%d", ntohs(me.sin6_port));
		}
		tstamp_printf("accepted connection: %s\n", addr_str);

		ret = read(conn_fd, rcvbuf, BUF_SIZE);
		if (ret >= BUF_SIZE)
			ret = BUF_SIZE - 1;
		rcvbuf[ret] = '\0';


		if (ret == (sizeof(COMPLETION_MSG) + sizeof(TSTAMP_STRING) - 1 ) && !strcmp(COMPLETION_MSG, rcvbuf + sizeof(TSTAMP_STRING))) {
			tstamp_printf("received success notification from remote system\n");
			tstamp_printf("\tmessage: '%s'\n", rcvbuf);
			tstamp_printf("exiting successfully\n");
			return EXIT_SUCCESS;
		}

		tstamp_printf("  received bad message: '%s' (%d bytes)\n", rcvbuf, ret);
		tstamp_printf("  expected '%s' (%ld bytes)\n", COMPLETION_MSG, sizeof(COMPLETION_MSG) - 1);
		close(conn_fd); /* close the fd & try to listen again */
	}
	exit_fail("error '%m' with accept\n");

	return EXIT_FAILURE;
}
