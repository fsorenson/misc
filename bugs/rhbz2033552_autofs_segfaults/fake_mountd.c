/*
	Frank Sorenson <sorenson@redhat.com>, 2022

	fake mountd program which:
		registers both tcp and udp port 20048 with rpcbind
		only responds to EXPORT calls
		returns an error when program version 2 is used
		returns exactly 2 paths, reversing the order over tcp vs. udp
		has a fixed 900 hosts per path
		the response is too large for udp


	# gcc -Wall /var/tmp/fake_mountd.c -o /var/tmp/fake_mountd -g -ltirpc -I/usr/include/tirpc

	# /var/tmp/fake_mountd

*/

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <ctype.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <netdb.h>
#include <string.h>
#include <time.h>

#include <rpc/rpc.h>

#define LISTEN_PORT 20048
#define LISTEN_BACKLOG 5
#define BUF_SIZE 1048576

#define ARRAY_SIZE(x) (sizeof(x)/sizeof(x[0]))

#define RPC_LAST_FRAG (0x80000000ULL)
#define RPC_FRAG_LEN_MASK (0x7fffffffULL)
#define RPCPROG_MOUNTD 100005
#define EVERYBODY "(everybody)"

struct xdr {
	char *p;
	int len;
	int max_len; // TODO
	char buf[0];
};

#define output(args...) do { \
	printf(args); \
	fflush(stdout); \
} while (0)

#define XDR_LEN(a) ((a+3)/4)
#define XDR_ROUNDUP(a)  (((a+3)/4)*4)

#define DECODE_32(x) ({ uint32_t ret = *(uint32_t*)(x->p); x->p += 4; x->len -= 4; ret; })
#define DECODE_64(x) ({ uint64_t ret = *(uint64_t*)(x->p); x->p += 8; x->len -= 8; ret; })

#define ENCODE_32(x, _var) do { \
	uint32_t *_p = (uint32_t *)x->p; \
	*_p = ntohl(_var); \
	x->p += 4; \
	x->len += 4; \
} while (0)
#define ENCODE_BYTES(x, _var, _len) do { \
	uint32_t roundup_len = XDR_ROUNDUP(_len); \
	uint32_t *_lenp = (uint32_t *)x->p; \
	char *_p = x->p + 4; \
	*_lenp = ntohl(_len); \
	memset(_p, 0x00, roundup_len); \
	memcpy(_p, _var, _len); \
	x->p += roundup_len + 4; \
	x->len += roundup_len + 4; \
} while (0)
#define ENCODE_STR(x, _var)  ENCODE_BYTES(x, _var, strlen(_var))

#define decode_alloc_bytes(x) ({ \
	uint32_t _len = XDR_ROUNDUP(ntohl(DECODE_32(x))); \
	char *buf; \
	if (_len > x->len) { \
		output("error: ran out bytes in stream - needed %d; have: %d\n", _len, x->len); \
		return EXIT_FAILURE; \
	} \
	buf = malloc(_len + 1); \
	memset(buf, 0, _len + 1); \
	memcpy(buf, x->p, _len); \
	x->p += _len; \
	x->len -= _len; \
	buf; \
})
#define DECODE_DISCARD_BYTES(x) ({ \
	uint32_t _len = XDR_ROUNDUP(ntohl(DECODE_32(x))); \
	if (_len > x->len) { \
		output("error: ran out bytes in stream - needed %d; have: %d\n", _len, x->len); \
		return EXIT_FAILURE; \
	} \
	x->p += _len; \
	x->len -= _len; \
	0; \
})

#define exit_fail(args...) do { \
	output(args); \
	exit(EXIT_FAILURE); \
} while (0)

static char *export_paths_udp[] = {
"/shortpath",
"/much/much/much/longer/path",
};
static char *export_paths_tcp[] = {
"/much/much/much/longer/path",
"/shortpath",
};

#define MIN_HOSTS 900
#define MAX_HOSTS 900

struct connection {
	int fd;
	struct sockaddr *addr;
	bool tcp_hdr;
};

int send_reply(struct connection connection, struct xdr *out_stream) {
	if (connection.tcp_hdr) {
		uint32_t *tcp_hdr_pos = (uint32_t *)out_stream->buf;
		*tcp_hdr_pos = htonl(RPC_LAST_FRAG + out_stream->len - 4);
		return write(connection.fd, out_stream->buf, out_stream->len);
	} else {
		return sendto(connection.fd, out_stream->buf, out_stream->len, 0,
			connection.addr, sizeof(struct sockaddr));
	}
}

static char *fmt_sockaddr(const struct sockaddr *addr) {
	const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *) addr;
	const struct sockaddr_un *sun = (const struct sockaddr_un *) addr;
	const struct sockaddr_in *sin = (const struct sockaddr_in *) addr;
	char buf[INET6_ADDRSTRLEN + 8];
	uint16_t port;
	size_t count;
	int len;

	switch (addr->sa_family) {
		case AF_LOCAL:
			return strndup(sun->sun_path, sizeof(sun->sun_path));
		case AF_INET:
			if (inet_ntop(AF_INET, (const void *)&sin->sin_addr.s_addr,
				buf, (socklen_t)sizeof(buf)) == NULL)
				goto out_err;
			port = ntohs(sin->sin_port);
			break;
		case AF_INET6:
			if (inet_ntop(AF_INET6, (const void *)&sin6->sin6_addr,
				buf, (socklen_t)sizeof(buf)) == NULL)
				goto out_err;
			port = ntohs(sin6->sin6_port);
			break;
		default:
			goto out_err;
	}
	count = sizeof(buf) - strlen(buf);
	len = snprintf(buf + strlen(buf), count, ":%u", port);
	if (len < 0 || (size_t)len > count)
		goto out_err;

	return strdup(buf);

out_err:
	return NULL;
}

void encode_paths(char **paths_list, int paths_count, struct xdr *out_stream, int offset) {
	int i;

	output("encoding path list with %d paths and offset: %d\n", paths_count, offset);
	for (i = 0 ; i < paths_count ; i++) {
		char *this_path = paths_list[ (i + offset) % paths_count ];
		int r = (random() % (MAX_HOSTS - MIN_HOSTS + 1)) + MIN_HOSTS;

		// encode the dir
		ENCODE_32(out_stream, 1); // value_follows
		ENCODE_STR(out_stream, this_path);

		if (r == 0) { // just encode '(everybody)'
			ENCODE_32(out_stream, 1);
			ENCODE_STR(out_stream, EVERYBODY);
		} else {
			char hostname[32];
			int j, k, l;
			for (j = 1 ; j <= r ; j++) {
				k = j / 250;
				l = (j % 250) + 1;

				snprintf(hostname, 32, "192.168.%d.%d", k, l);
				ENCODE_32(out_stream, 1);
				ENCODE_STR(out_stream, hostname);
			}
		}
		ENCODE_32(out_stream, 0); // no more hosts
	}
	ENCODE_32(out_stream, 0); // no more paths
}

int process_rpc(struct connection connection, char *buf, int len) {
	static int call_iter = 0;
	int ret = EXIT_FAILURE;
	struct xdr *in_stream = malloc(len + offsetof(struct xdr, buf));
	struct xdr *out_stream = malloc(BUF_SIZE + offsetof(struct xdr, buf));

	memcpy(in_stream->buf, buf, len);
	in_stream->p = in_stream->buf;
	in_stream->len = len;

	memset(out_stream, 0, BUF_SIZE + offsetof(struct xdr, buf));
	out_stream->p = out_stream->buf;

	if (connection.tcp_hdr) {
		uint32_t expected_len = ntohl(DECODE_32(in_stream)) & RPC_FRAG_LEN_MASK;
		if (expected_len != in_stream->len)
			output("WARNING: expected length: %d, remaining length: %d\n", expected_len, in_stream->len);
	}
	uint32_t rpc_xid = ntohl(DECODE_32(in_stream));
	uint32_t rpc_msgtyp = ntohl(DECODE_32(in_stream));

	uint32_t rpc_vers = ntohl(DECODE_32(in_stream));
	uint32_t rpc_prog = ntohl(DECODE_32(in_stream));
	uint32_t rpc_progvers = ntohl(DECODE_32(in_stream));
	uint32_t rpc_proc = ntohl(DECODE_32(in_stream));

	output("RPC V%d %s - xid: 0x%08x\n", rpc_vers, rpc_msgtyp == 0 ? "Call" : "Reply", rpc_xid);
	output("RPC program: %d  V%d on %s\n", rpc_prog, rpc_progvers, connection.tcp_hdr ? "tcp" : "udp");
	output("RPC procedure: %d\n", rpc_proc);

	DECODE_32(in_stream); // auth flavor
	DECODE_DISCARD_BYTES(in_stream); // just skip bytes
	DECODE_32(in_stream); // verf flavor
	DECODE_DISCARD_BYTES(in_stream); // just skip bytes

	if (rpc_msgtyp != CALL) {
		output("invalid rpc message: %d is not a call\n", rpc_msgtyp);

		if (connection.tcp_hdr)
			ENCODE_32(out_stream, 0);

		ENCODE_32(out_stream, rpc_xid);
		ENCODE_32(out_stream, REPLY); // rpc_msgtyp == REPLY
		ENCODE_32(out_stream, MSG_DENIED);

	       goto out;
	}

	if (connection.tcp_hdr)
		ENCODE_32(out_stream, 0);

	ENCODE_32(out_stream, rpc_xid);
	ENCODE_32(out_stream, REPLY); // rpc_msgtyp == REPLY
	ENCODE_32(out_stream, MSG_ACCEPTED); // rpc.replystat == accepted

	ENCODE_32(out_stream, 0); // null flavor
	ENCODE_32(out_stream, 0); // null length

	if (rpc_prog != RPCPROG_MOUNTD) {
		output("invalid rpc program: %d\n", rpc_prog);
		ENCODE_32(out_stream, RPC_PROGNOTREGISTERED);

		goto out;
	}

	if (rpc_proc == 0) { // NULL

	} else if (rpc_proc == 5) { // EXPORT
		// if rpc.programversion == 2, return an error
		if (rpc_progvers < 1 || rpc_progvers == 2 || rpc_progvers > 3) {
			ENCODE_32(out_stream, 2); // remote can't support version # (2)
			ENCODE_32(out_stream, 1); // minimum version
			ENCODE_32(out_stream, 3); // maximum version
		} else {
			ENCODE_32(out_stream, 0); // rpc.state_accept == 0

			if (connection.tcp_hdr)
				encode_paths(export_paths_tcp, ARRAY_SIZE(export_paths_tcp), out_stream, call_iter);
			else
				encode_paths(export_paths_udp, ARRAY_SIZE(export_paths_udp), out_stream, call_iter);
		}

		ret = EXIT_SUCCESS;
//		call_iter++;
	} else {
		output("rpc procedure %d not implemented\n", rpc_proc);
		ENCODE_32(out_stream, RPC_PROCUNAVAIL);
	}

out:
	send_reply(connection, out_stream);
	output("sent response with %d bytes\n\n", out_stream->len);

	free(in_stream);
	free(out_stream);

	return ret;
}

int setup_sock(int type) {
	struct sockaddr_in6 me;
	socklen_t addr_size = sizeof(me);
	char *type_name;
	const int yes_flag = 1;
	int fd;

	if (type == SOCK_STREAM)
		type_name = "tcp";
	else if (type == SOCK_DGRAM)
		type_name = "udp";
	else
		exit_fail("unknown socket type %d\n", type);

	if ((fd = socket(AF_INET, type, 0)) < 0)
		exit_fail("error '%m' opening %s socket\n", type_name);
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes_flag, sizeof(int)) < 0)
		exit_fail("error '%m' calling setsockopt(SO_REUSEADDR) on %s socket\n", type_name);
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &yes_flag, sizeof(int)) < 0)
		exit_fail("error '%m' calling setsockopt(SO_REUSEPORT) on %s socket\n", type_name);

	memset(&me, 0, addr_size);
	((struct sockaddr_in *)&me)->sin_family = AF_INET;
	((struct sockaddr_in *)&me)->sin_addr.s_addr = INADDR_ANY;
	((struct sockaddr_in *)&me)->sin_port = htons(LISTEN_PORT);

	if (bind(fd, (struct sockaddr *)&me, addr_size) < 0)
		exit_fail("error '%m' calling bind for %s socket with po0rt %d\n", type_name, LISTEN_PORT);

	if (type == SOCK_STREAM) {
		if (listen(fd, LISTEN_BACKLOG) < 0)
			exit_fail("error '%m' calling listen for tcp socket\n");
	}

	return fd;
}
void reregister(void) {
	int i;

	for (i = 3 ; i >= 1 ; i--) {
		pmap_unset(RPCPROG_MOUNTD, i);
		pmap_set(RPCPROG_MOUNTD, i, IPPROTO_TCP, LISTEN_PORT);
		pmap_set(RPCPROG_MOUNTD, i, IPPROTO_UDP, LISTEN_PORT);
	}
}

int main(int argc, char *argv[]) {
	struct sockaddr_in6 me, peer;
	struct connection connection;
	char *local_str, *remote_str;

	char *rcvbuf = malloc(BUF_SIZE);

	int tcp_fd = setup_sock(SOCK_STREAM);
	int udp_fd = setup_sock(SOCK_DGRAM);

	reregister();

	output("listening\n");
	while (42) {
		int nfds = tcp_fd > udp_fd ? tcp_fd : udp_fd;
		int ret;

		fd_set read_mask;
		FD_ZERO(&read_mask);
		FD_SET(tcp_fd, &read_mask);
		FD_SET(udp_fd, &read_mask);

		if ((ret = select(nfds + 1, &read_mask, NULL, NULL, NULL)) > 0) {
			if (FD_ISSET(tcp_fd, &read_mask)) {
				socklen_t len = sizeof(me);
				int conn_fd;

				len = sizeof(peer);
				if ((conn_fd = accept(tcp_fd, (struct sockaddr *)&peer, &len)) >= 0) {
					len = sizeof(me);
					getsockname(conn_fd, (struct sockaddr *)&me, &len);
					len = sizeof(peer);
					getpeername(conn_fd, (struct sockaddr *)&peer, &len);

					ret = read(conn_fd, rcvbuf, BUF_SIZE);
					if (ret >= BUF_SIZE)
						ret = BUF_SIZE - 1;

					local_str = fmt_sockaddr((struct sockaddr *)&me);
					remote_str = fmt_sockaddr((struct sockaddr *)&peer);
					output("received %d bytes from tcp connection %s <=> %s\n", ret, local_str, remote_str);
					if (local_str)
						free(local_str);
					if (remote_str)
						free(remote_str);

					connection.fd = conn_fd;
					connection.tcp_hdr = true;
					process_rpc(connection, rcvbuf, ret);
					close(conn_fd); /* close the fd & try to listen again */
				} else {
					output("error '%m' calling accept on tcp socket\n");
				}
			}
			if (FD_ISSET(udp_fd, &read_mask)) {
				socklen_t len = sizeof(peer);

				connection.fd = udp_fd;
				connection.addr = (struct sockaddr *)&peer;
				connection.tcp_hdr = false;
				memset(rcvbuf, 0, BUF_SIZE);
				ret = recvfrom(connection.fd, rcvbuf, BUF_SIZE, 0,
					connection.addr, &len);
				if (ret >= BUF_SIZE)
					ret = BUF_SIZE - 1;

				remote_str = fmt_sockaddr(connection.addr);

				output("received %d bytes over udp from %s\n", ret, remote_str);
				if (remote_str)
					free(remote_str);

				process_rpc(connection, rcvbuf, ret);
			}
		}
	}
	return EXIT_FAILURE;
}
