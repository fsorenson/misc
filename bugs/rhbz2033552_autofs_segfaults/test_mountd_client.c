#include <stdio.h>
#include <stdlib.h>
#include <rpc/rpc.h>

#define MOUNTDPROG	(uint32_t)100005
#define MOUNTDVERSION	(uint32_t)1

#ifndef NULLPROC
#define NULLPROC	(uint32_t)0
#endif

int main(int argc, char *argv[]) {
	char *host = "localhost";
	int error;

	if (argc == 2)
		host = argv[1];

	if ((error = rpc_call(host, MOUNTDPROG, MOUNTDVERSION, NULLPROC,
		(xdrproc_t)xdr_void, NULL, (xdrproc_t)xdr_void, NULL, "udp"))) {

		printf("error: rpc_call failed %d\n", error);
		printf("MOUNTDPROG: %d MOUNTDVERSION: %d NULLPROC: %d\n",
			MOUNTDPROG, MOUNTDVERSION, NULLPROC);
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
