// Frank Sorenson <sorenson@redhat.com>, 2023

// gcc -Wall rpcdump.c -o rpcdump -ltirpc -I/usr/include/tirpc 2>&1

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stddef.h>
#include <netdb.h>
#include <rpc/rpc.h>
#include <tirpc/rpc/pmap_prot.h>

#define BUF_SIZE 32768

#ifndef PMAPPROG
#define PMAPPROG	(uint32_t)100000 /* which program to call */
#define PMAPVERS	(uint32_t)2 /* which program version */
#define PMAPPROC_DUMP	(uint32_t)4 /* which procedure number to call */
#endif

#define DECODE_U32(x) ({ int32_t l; XDR_GETINT32(x, &l); l; })

bool decode_one_entry(XDR *xdrs, void *buf) {
	struct rpcent *rpc;

	uint32_t prog = DECODE_U32(xdrs);
	uint32_t vers = DECODE_U32(xdrs);
	uint32_t prot = DECODE_U32(xdrs);
	uint32_t port = DECODE_U32(xdrs);

	rpc = getrpcbynumber(prog);
	printf("prog: %d (%s), vers: %d, protocol: %d (%s), port: %d\n",
		prog, rpc->r_name, vers, prot,
		prot == IPPROTO_TCP ? "tcp" :
		prot == IPPROTO_UDP ? "udp" : "unknown",
		port);

	return true;
}

bool decode_dump_stream(XDR *xdrs, void *buf) {
	bool more_elements = true;
	int32_t l;

	XDR_GETINT32(xdrs, &l);
	more_elements = !!l;

	while (more_elements) {
		decode_one_entry(xdrs, buf);

		XDR_GETINT32(xdrs, &l);
		more_elements = !! l;
	}
	return true;
}

// rpc_call(const char *host, const rpcprog_t prognum, const rpcvers_t versnum, const rpcproc_t procnum, const xdrproc_t inproc,
//       const char *in, const xdrproc_t outproc, char *out, const char *nettype);
int main(int argc, char *argv[]) {
	char outbuf[BUF_SIZE];

	char *host = "localhost";
	int error;

	if (argc == 2)
		host = argv[1];

	if ((error = rpc_call(host, PMAPPROG, PMAPVERS, PMAPPROC_DUMP,
		(xdrproc_t)xdr_void, NULL, (xdrproc_t)decode_dump_stream, outbuf, "tcp"))) {
		printf("error: rpc_call failed: %d\n", error);
	}

	return EXIT_SUCCESS;
}
