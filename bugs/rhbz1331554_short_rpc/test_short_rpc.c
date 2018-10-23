/*
	Frank Sorenson <sorenson@redhat.com> 2016
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <errno.h>
#include <sys/types.h>
#include <netdb.h>
#include <string.h>
#include <signal.h>
#include <poll.h>

static char sendbuf[]  = {0x80, 0x00, 0x00, 0x3c, 0x49, 0x1f, 0xcc, 0x7d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01, 0x86, 0xa0, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x86, 0xa0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

#define SEND_BUF_LEN (sizeof(sendbuf))
#define RECV_BUF_LEN (1024)
#define SLEEP_TIME 100 /* us */
#define FIRST_SEND_FLAGS (MSG_DONTWAIT) /* MSG_MORE holds the data, and rpcbind doesn't disconnect */
#define SECOND_SEND_FLAGS (MSG_DONTWAIT)
#define STOP_COUNT 100 /* stop after this many calls */

#define exit_fail(args...) do { \
	printf(args); fflush(stdout); exit(EXIT_FAILURE); } while (0)

#define error_exit_fail(args...) do { \
	printf("Error %d: %s - ", errno, strerror(errno)); \
	exit_fail(args); \
	} while (0)

#define debug(args...) do { \
	printf(args); fflush(stdout); \
	} while (0)

void handle_sigpipe(int sig) {
	exit_fail("caught SIGPIPE\n");
}

int main(int argc, char *argv[]) {
	char *host = "127.0.0.1";
	struct addrinfo hints;
	struct addrinfo *res;
	char recvbuf[RECV_BUF_LEN];
	int yes_flag = 1;
	int fd;
	int ret;
	int split = SEND_BUF_LEN;
	struct sigaction sa;
	unsigned long counter = 0;
	struct pollfd pfd[1];

	if (argc == 3) {
		host = argv[1];
		split = (int)strtol(argv[2], NULL, 0);
	} else
		exit_fail("usage: %s <host> <split>\n\t(0 <= split <= %lu)\n",
			argv[0], SEND_BUF_LEN);
	if ((split < 0) || (split > SEND_BUF_LEN)) {
		debug("split value '%d' out-of-range (0 .. %ld)\n", split, SEND_BUF_LEN);
		split = SEND_BUF_LEN;
	}

	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sa.sa_handler = &handle_sigpipe;
	sigaction(SIGPIPE, &sa, NULL);

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC; /* we'll take either AF_INET or AF_INET6 */
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	if ((ret = getaddrinfo(host, "111", &hints, &res) != 0))
		error_exit_fail("calling getaddrinfo\n");

	if ((fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol)) == -1)
		error_exit_fail("calling socket\n");
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes_flag, sizeof(int)) == -1)
		error_exit_fail("calling setsockopt\n");
	if (connect(fd, res->ai_addr, res->ai_addrlen) == -1)
		error_exit_fail("calling connect\n");
	freeaddrinfo(res);

	pfd[0].fd = fd;
	pfd[0].events = POLLIN;

	while (counter++ < STOP_COUNT) {
		debug("%lu: ", counter);
		if ((ret = send(fd, sendbuf, split, FIRST_SEND_FLAGS)) != split)
			error_exit_fail("sending %d bytes\n", split);
		debug("sent %d bytes... ", split);
		if (split < SEND_BUF_LEN) {
			usleep(SLEEP_TIME);
			if ((ret = send(fd, sendbuf + split, SEND_BUF_LEN - split, SECOND_SEND_FLAGS)) != SEND_BUF_LEN - split)
				error_exit_fail("sending remaining %ld bytes\n", SEND_BUF_LEN - split);
			debug("sent %d bytes...  ", ret);
		}

		pfd[0].revents = 0;
		ret = poll(pfd, 1, -1);
		if (ret <= 0)
			error_exit_fail("waiting for reply\n");
		if (pfd[0].revents & POLLIN) {
			if ((ret = recv(fd, recvbuf, RECV_BUF_LEN, 0)) == -1)
				error_exit_fail("calling recv\n");
			debug("received %d bytes\n", ret);
		}
	}
	debug("completed %d rpc calls\n", STOP_COUNT);

	return 0;
}
