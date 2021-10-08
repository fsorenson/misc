#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

#include <sys/types.h>          /* See NOTES */
#include <sys/socket.h>

#include <tirpc/rpc/rpc.h>

//#include <arpa/inet>

//#include <rpc/rpc.h>

/*
       bool_t pmap_set(unsigned long prognum, unsigned long versnum,
                       unsigned int protocol, unsigned short port);
       bool_t pmap_set(unsigned long prognum, unsigned long versnum,
                       unsigned int protocol, unsigned short port);

              A user interface to the portmap service, which establishes a mapping between the triple [prognum,versnum,protocol] and port on the machine's portmap service.  The value of  protocol  is
              most likely IPPROTO_UDP or IPPROTO_TCP.  This routine returns one if it succeeds, zero otherwise.  Automatically done by svc_register().


       bool_t pmap_unset(unsigned long prognum, unsigned long versnum);

              A  user  interface  to the portmap service, which destroys all mapping between the triple [prognum,versnum,*] and ports on the machine's portmap service.  This routine returns one if it
              succeeds, zero otherwise.
*/


#define RPCPROG_NFS	100003
#define RPCPROG_NLM	100021
#define RPCPROG_STATD	100024

int main(int argc, char *argv[]) {
	bool ret;

//	ret = pmap_set(RPCPROG_NFS, 5, IPPROTO_TCP, 2049);
//	ret = pmap_unset(RPCPROG_NFS, 5);

/*
	pmap_unset(RPCPROG_STATD, 1);
	pmap_set(RPCPROG_STATD, 1, IPPROTO_TCP, 2049);
	pmap_set(RPCPROG_STATD, 1, IPPROTO_UDP, 2049);
*/


//    100024    1   udp  51212  status
//    100024    1   tcp  51212  status

//    100021    1   udp  52244  nlockmgr
//    100021    3   udp  52244  nlockmgr
//    100021    4   udp  52244  nlockmgr
//    100021    1   tcp  36202  nlockmgr
//    100021    3   tcp  36202  nlockmgr
//    100021    4   tcp  36202  nlockmgr

	pmap_unset(RPCPROG_NLM, 1);
	pmap_unset(RPCPROG_NLM, 3);
	pmap_unset(RPCPROG_NLM, 4);
	pmap_set(RPCPROG_NLM, 1, IPPROTO_TCP, 2049);
	pmap_set(RPCPROG_NLM, 3, IPPROTO_TCP, 2049);
	pmap_set(RPCPROG_NLM, 4, IPPROTO_TCP, 2049);
	pmap_set(RPCPROG_NLM, 1, IPPROTO_UDP, 2049);
	pmap_set(RPCPROG_NLM, 3, IPPROTO_UDP, 2049);
	pmap_set(RPCPROG_NLM, 4, IPPROTO_UDP, 2049);


	return EXIT_SUCCESS;
}

